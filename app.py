import streamlit as st
import pandas as pd
import pyshark
import json
from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev
import tempfile

st.set_page_config(page_title="PCAP IOC & C2 Dashboard", layout="wide")

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
    except AttributeError:
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
    beacons = detect_beaconing(ip_time_map)
    return pd.DataFrame(iocs), beacons

# ---- UI START ----
st.title("🔍 PCAP IOC & C2 Detection Dashboard")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        temp.write(uploaded_file.read())
        temp_path = temp.name

    with st.spinner("Analyzing PCAP... this may take a minute"):
        df_iocs, c2_candidates = analyze_pcap(temp_path)

    st.success("Analysis Complete!")

    # IOC Table
    st.subheader("📌 Extracted IOCs")
    st.dataframe(df_iocs, use_container_width=True)

    # C2 Beaconing Detection
    st.subheader("⚠️ C2 Beaconing Candidates")
    if c2_candidates:
        df_c2 = pd.DataFrame(c2_candidates)
        st.dataframe(df_c2, use_container_width=True)
    else:
        st.info("No clear C2 patterns detected.")

    # Downloads
    st.subheader("📁 Download Reports")
    st.download_button("📥 Download IOCs (CSV)", df_iocs.to_csv(index=False), "ioc_report.csv")
    st.download_button("📥 Download IOCs (JSON)", df_iocs.to_json(orient="records", indent=2), "ioc_report.json")
    st.download_button("📥 Download C2 Report (JSON)", json.dumps(c2_candidates, indent=2), "c2_candidates.json")