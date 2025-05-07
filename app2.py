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
from dotenv import load_dotenv

load_dotenv()
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")

st.set_page_config(page_title="PCAP IOC & Threat Dashboard", layout="wide")

# ------------------- Threat Intelligence -------------------

def check_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSE_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 30}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=5)
        data = response.json()['data']
        return {
            "abuseScore": data["abuseConfidenceScore"],
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", "")
        }
    except:
        return {"abuseScore": -1, "country": "", "isp": ""}

def check_virustotal_ip(ip):
    headers = {"x-apikey": VT_KEY}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
    except:
        return {"malicious": -1, "suspicious": -1}

def check_virustotal_domain(domain):
    headers = {"x-apikey": VT_KEY}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        response = requests.get(url, headers=headers, timeout=5)
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return {
            "domain_malicious": stats.get("malicious", 0),
            "domain_suspicious": stats.get("suspicious", 0)
        }
    except:
        return {"domain_malicious": -1, "domain_suspicious": -1}

# ------------------- PCAP Analysis -------------------

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
        time.sleep(1.2)  # Rate limit
    return enriched

def enrich_domains(df):
    seen = {}
    enriched = []
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

# ------------------- Streamlit UI -------------------

st.title("🔐 PCAP IOC & Threat Dashboard")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    with st.spinner("Processing PCAP and enriching IOCs..."):
        df_iocs, c2_candidates = analyze_pcap(tmp_path)

    st.success("✅ Analysis Complete!")

    # ---- IOCs ----
    st.subheader("📌 Extracted IOCs with Domain Threat Scores")
    st.dataframe(df_iocs, use_container_width=True)

    # ---- C2 Table ----
    st.subheader("⚠️ C2 Beaconing Candidates with Threat Enrichment")
    df_c2 = pd.DataFrame(c2_candidates)
    
    def highlight_threat(val):
        color = 'red' if val > 10 else 'orange' if val > 5 else 'green'
        return f'background-color: {color}'

    st.dataframe(df_c2.style.applymap(highlight_threat, subset=['threat_score']), use_container_width=True)

    # ---- Charts ----
    st.subheader("📊 Visualizations")

    # Bar: connections per IP
    st.markdown("**Connections per Suspected C2 IP**")
    fig1, ax1 = plt.subplots()
    df_c2.plot(kind='bar', x='ip', y='connections', ax=ax1, legend=False, color='tomato')
    ax1.set_ylabel("Connections")
    ax1.set_title("Connections per IP")
    st.pyplot(fig1)

    # Line: beacon intervals
    selected_ip = st.selectbox("Select IP for beacon interval chart", df_c2['ip'] if not df_c2.empty else [])
    if selected_ip:
        ts = sorted(df_iocs[df_iocs['dst_ip'] == selected_ip]['timestamp'])
        times = [datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f") for t in ts]
        intervals = [(times[i+1] - times[i]).total_seconds() for i in range(len(times)-1)]
        if intervals:
            fig2, ax2 = plt.subplots()
            ax2.plot(intervals, marker='o', linestyle='-', color='steelblue')
            ax2.set_title(f"Beacon Intervals to {selected_ip}")
            ax2.set_ylabel("Interval (sec)")
            st.pyplot(fig2)

    # ---- Downloads ----
    st.subheader("📁 Download Reports")
    st.download_button("📥 IOCs CSV", df_iocs.to_csv(index=False), "ioc_report.csv")
    st.download_button("📥 IOCs JSON", df_iocs.to_json(orient="records", indent=2), "ioc_report.json")
    st.download_button("📥 C2 JSON", json.dumps(c2_candidates, indent=2), "c2_candidates.json")