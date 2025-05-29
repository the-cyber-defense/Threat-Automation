# sentinel_threat_hunting_script.py

"""
Project: Azure Sentinel Threat Hunting Automation
Author: Tyler Reid

Demonstrates:
- Querying Sentinel Logs via API (Python)
- Threat Hunting logic (abnormal logins, beaconing detection)
- MITRE ATT&CK Mapping
- Risk Prioritization
"""

import requests
import json
import datetime

# ====== CONFIGURATION ======
TENANT_ID = "YOUR_TENANT_ID"
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"
WORKSPACE_ID = "YOUR_WORKSPACE_ID"

# Azure Resource URLs
TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/token"
API_URL = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"

# ====== FUNCTIONS ======

def get_azure_token():
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "resource": "https://api.loganalytics.io/"
    }
    response = requests.post(TOKEN_URL, data=payload)
    if response.status_code == 200:
        token = response.json()["access_token"]
        return token
    else:
        print("[-] Failed to get Azure token.")
        return None

def run_kql_query(token, kql_query):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    params = {
        "query": kql_query
    }
    response = requests.post(API_URL, headers=headers, json=params)
    if response.status_code == 200:
        return response.json()
    else:
        print("[-] Failed to run KQL query.")
        return None

def parse_results(result_json):
    if not result_json or "tables" not in result_json:
        print("[-] No results to parse.")
        return
    rows = result_json["tables"][0]["rows"]
    for row in rows:
        print("[ALERT] Anomaly Detected:", row)

# ====== THREAT HUNTING QUERIES ======

# Detect Multiple Failed Logins Followed by Success
FAILED_LOGIN_QUERY = """
SigninLogs
| where ResultType == "50074" or ResultType == "50076"
| summarize Attempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where Attempts > 5
"""

# Detect Beaconing Behavior
BEACONING_QUERY = """
AzureNetworkAnalytics_CL
| where RemotePort_s == "443" or RemotePort_s == "80"
| summarize count() by RemoteIP_s, bin(TimeGenerated, 5m)
| where count_ > 50
"""

# ====== MAIN ======

if __name__ == "__main__":
    token = get_azure_token()
    if token:
        print("\n[INFO] Running Failed Login Hunt...")
        failed_login_results = run_kql_query(token, FAILED_LOGIN_QUERY)
        parse_results(failed_login_results)

        print("\n[INFO] Running Beaconing Detection Hunt...")
        beaconing_results = run_kql_query(token, BEACONING_QUERY)
        parse_results(beaconing_results)

# ====== SAMPLE MITRE ATT&CK MAPPING ======
"""
Findings:
- Multiple failed login attempts suggest Brute Force (T1110)
- High-frequency communications to a remote IP suggest C2 Beaconing (T1071)

Risk Priority:
- Immediate review and containment of suspicious accounts or devices.
- Possible follow-up with endpoint telemetry from CrowdStrike or Defender.
"""