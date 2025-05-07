
#install requests pandas via bash - pip install requests pandas

import requests
import pandas as pd

# === Config ===
crowdstrike_client_id = "YOUR_CROWDSTRIKE_CLIENT_ID"
crowdstrike_client_secret = "YOUR_CROWDSTRIKE_CLIENT_SECRET"
virustotal_api_key = "YOUR_VIRUSTOTAL_API_KEY"
iocs = ["8e4f4c59a248e2c18122f6d5f479fd66", "1.1.1.1"]  # mix of hashes and IPs

# === CrowdStrike Auth ===
def get_crowdstrike_token():
    url = "https://api.crowdstrike.com/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "client_id": crowdstrike_client_id,
        "client_secret": crowdstrike_client_secret
    }
    resp = requests.post(url, headers=headers, data=data)
    resp.raise_for_status()
    return resp.json()["access_token"]

# === Query CrowdStrike ===
def search_crowdstrike(ioc, token):
    url = f"https://api.crowdstrike.com/indicators/entities/indicators/v1"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"values": ioc}
    resp = requests.get(url, headers=headers, params=params)
    if resp.status_code == 200 and resp.json()["resources"]:
        return resp.json()["resources"][0]
    return {}

# === Query VirusTotal ===
def search_virustotal(ioc):
    if "." in ioc:
        vt_type = "ip-address"
    else:
        vt_type = "file"
    url = f"https://www.virustotal.com/api/v3/{vt_type}s/{ioc}"
    headers = {"x-apikey": virustotal_api_key}
    resp = requests.get(url, headers=headers)
    if resp.status_code == 200:
        data = resp.json()["data"]
        return {
            "last_analysis_stats": data.get("attributes", {}).get("last_analysis_stats", {}),
            "malicious_tags": data.get("attributes", {}).get("tags", [])
        }
    return {}

# === Main ===
def enrich_iocs(iocs):
    token = get_crowdstrike_token()
    results = []

    for ioc in iocs:
        cs_data = search_crowdstrike(ioc, token)
        vt_data = search_virustotal(ioc)

        result = {
            "IOC": ioc,
            "CrowdStrike_Type": cs_data.get("type"),
            "CrowdStrike_Rating": cs_data.get("severity", "n/a"),
            "VT_Malicious": vt_data.get("last_analysis_stats", {}).get("malicious", "n/a"),
            "VT_Tags": ",".join(vt_data.get("malicious_tags", []))
        }
        results.append(result)

    return pd.DataFrame(results)

# === Run ===
df = enrich_iocs(iocs)
print(df.to_string(index=False))