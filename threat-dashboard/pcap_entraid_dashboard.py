# pcap_entraid_dashboard.py

import os
import json
import time
import tempfile
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import requests
import streamlit as st
from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev

# Use secrets from Streamlit Cloud
ABUSE_KEY = st.secrets["ABUSEIPDB_API_KEY"]
VT_KEY = st.secrets["VT_API_KEY"]

st.set_page_config(page_title="Threat Dashboard", layout="wide")

# ---------- Threat Intelligence Functions ----------

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 30}
        r = requests.get(url, headers=headers, params=params, timeout=5)
        data = r.json()["data"]
        return {
            "abuseScore": data.get("abuseConfidenceScore", -1),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", "")
        }
    except:
        return {"abuseScore": -1, "country": "", "isp": ""}

def check_virustotal_ip(ip):
    try:
        headers = {"x-apikey": VT_KEY}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        r = requests.get(url, headers=headers, timeout=5)
        stats = r.json()['data']['attributes']['last_analysis_stats']
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
    except:
        return {"malicious": -1, "suspicious": -1}

def check_virustotal_domain(domain):
    try:
        headers = {"x-apikey": VT_KEY}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(url, headers=headers, timeout=5)
        stats = r.json()['data']['attributes']['last_analysis_stats']
        return {
            "domain_malicious": stats.get("malicious", 0),
            "domain_suspicious": stats.get("suspicious", 0)
        }
    except:
        return {"domain_malicious": -1, "domain_suspicious": -1}

# ---------- PCAP Parsing & C2 Detection ----------

def extract_iocs(packet):
    try:
        return {
            'timestamp': str(packet.sniff_time),
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'protocol': packet.transport_layer,
            'length': int(packet.length),
            'domain': getattr(packet.dns, 'qry_name', '') if 'DNS' in packet else '',
            'http_host': getattr(packet.http, 'host', '') if 'HTTP' in packet else '',
            'http_uri': getattr(packet.http, 'request_uri', '') if 'HTTP' in packet else ''
        }
    except:
        return None

def detect_beaconing(ip_timestamps, threshold=0.1):
    beacons = []
    for ip, times in ip_timestamps.items():
        if len(times) < 4:
            continue
        deltas = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        if len(deltas) < 2:
            continue
        try:
            avg = mean(deltas)
            sdev = stdev(deltas)
            if sdev < threshold * avg:
                beacons.append({
                    'ip': ip,
                    'connections': len(times),
                    'avg_interval_sec': round(avg, 2),
                    'std_dev': round(sdev, 2)
                })
        except:
            continue
    return beacons

def enrich_c2_data(c2_list):
    enriched = []
    for entry in c2_list:
        ip = entry['ip']
        abuse = check_abuseipdb(ip)
        vt = check_virustotal_ip(ip)
        entry.update({
            'abuseScore': abuse['abuseScore'],
            'country': abuse['country'],
            'malicious': vt['malicious'],
            'suspicious': vt['suspicious'],
            'threat_score': abuse['abuseScore'] + vt['malicious'] * 5 + vt['suspicious'] * 3
        })
        enriched.append(entry)
        time.sleep(1.2)
    return enriched

def enrich_domains(df):
    seen = {}
    for domain in df['domain'].dropna().unique():
        if not domain or domain in seen:
            continue
        vt = check_virustotal_domain(domain)
        seen[domain] = vt
        time.sleep(1.2)
    df['domain_malicious'] = df['domain'].apply(lambda d: seen.get(d, {}).get('domain_malicious', 0))
    df['domain_suspicious'] = df['domain'].apply(lambda d: seen.get(d, {}).get('domain_suspicious', 0))
    return df

def analyze_pcap(pcap_path):
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    iocs = []
    ip_time_map = defaultdict(list)
    for pkt in cap:
        ioc = extract_iocs(pkt)
        if ioc:
            iocs.append(ioc)
            ip_time_map[ioc['dst_ip']].append(datetime.strptime(ioc['timestamp'], "%Y-%m-%d %H:%M:%S.%f"))
    cap.close()
    df_iocs = pd.DataFrame(iocs)
    df_iocs = enrich_domains(df_iocs)
    c2_candidates = detect_beaconing(ip_time_map)
    c2_candidates = enrich_c2_data(c2_candidates)
    return df_iocs, c2_candidates

# ---------- Streamlit UI ----------

st.title("🛡️ PCAP & Entra ID Threat Dashboard")

uploaded_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])
if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name
    st.spinner("Analyzing...")
    df_iocs, c2_candidates = analyze_pcap(tmp_path)
    st.success("PCAP Analysis Complete")
    st.subheader("Extracted IOCs")
    st.dataframe(df_iocs)
    st.subheader("C2 Candidates")
    df_c2 = pd.DataFrame(c2_candidates)
    st.dataframe(df_c2)

# ---------- Entra ID Login Analysis ----------

st.markdown("---")
st.header("🔐 Entra ID Login Attempt Analysis")

login_file = st.file_uploader("Upload Entra ID Sign-In Logs (CSV or JSON)", type=["csv", "json"])
if login_file:
    try:
        if login_file.name.endswith('.csv'):
            login_df = pd.read_csv(login_file)
        else:
            login_df = pd.read_json(login_file)

        login_df['timestamp'] = pd.to_datetime(login_df['timestamp'])
        login_df['status'] = login_df['status'].str.title()

        unique_ips = login_df['ipAddress'].dropna().unique()
        enrichment = []
        for ip in unique_ips:
            abuse = check_abuseipdb(ip)
            vt = check_virustotal_ip(ip)
            enrichment.append({
                "ip": ip,
                "abuseScore": abuse['abuseScore'],
                "country": abuse['country'],
                "malicious": vt['malicious'],
                "suspicious": vt['suspicious'],
                "threat_score": abuse['abuseScore'] + vt['malicious'] * 5 + vt['suspicious'] * 3
            })
            time.sleep(1.2)

        enrich_df = pd.DataFrame(enrichment)
        login_df = login_df.merge(enrich_df, how='left', left_on='ipAddress', right_on='ip')

        st.subheader("📌 Enriched Login Events")
        st.dataframe(login_df, use_container_width=True)

        st.markdown("**Login Attempt Status Breakdown**")
        st.bar_chart(login_df['status'].value_counts())

        st.markdown("**Login Attempts by Source IP**")
        ip_counts = login_df['ipAddress'].value_counts().reset_index()
        ip_counts.columns = ['IP Address', 'Attempts']
        st.bar_chart(ip_counts.set_index('IP Address'))

        st.download_button("📥 Download Enriched Login Log (CSV)", login_df.to_csv(index=False), "entra_logins.csv")

    except Exception as e:
        st.error(f"Error processing login data: {e}")
