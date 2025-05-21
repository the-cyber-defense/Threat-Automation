import os
import json
import requests
import subprocess
from datetime import datetime, timedelta
from msal import ConfidentialClientApplication

# ----------------------------
# CONFIGURATION
# ----------------------------
TENANT_ID = "your_tenant_id"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
WORKSPACE_ID = "your_workspace_id"
ABUSEIPDB_API_KEY = "your_abuseipdb_key"
VT_API_KEY = "your_virustotal_key"
NMAP_PATH = "nmap"
OUTPUT_DIR = "incident_reports"

# ----------------------------
# SENTINEL: Get Azure Token
# ----------------------------
def get_azure_token():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = ConfidentialClientApplication(CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET)
    token = app.acquire_token_for_client(scopes=["https://api.loganalytics.io/.default"])
    return token["access_token"]

# ----------------------------
# SENTINEL: Query Alerts
# ----------------------------
def get_sentinel_alerts(token, time_range_minutes=60):
    url = f"https://api.loganalytics.io/v1/workspaces/{WORKSPACE_ID}/query"
    query = f"""
        SecurityAlert
        | where TimeGenerated > ago({time_range_minutes}m)
        | project TimeGenerated, SystemAlertId, AlertName, CompromisedEntity, Entities
    """
    headers = {"Authorization": f"Bearer {token}"}
    data = {"query": query}
    response = requests.post(url, headers=headers, json=data)
    response.raise_for_status()
    alerts = response.json().get("tables", [])[0].get("rows", [])
    return alerts

# ----------------------------
# Threat Intelligence Enrichment with VirusTotal and AbuseIPDB
# ----------------------------
def abuseipdb_lookup(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    return requests.get(url, headers=headers, params=params).json()

def virustotal_lookup(domain_or_ip):
    url = f"https://www.virustotal.com/api/v3/domains/{domain_or_ip}"
    headers = {"x-apikey": VT_API_KEY}
    return requests.get(url, headers=headers).json()

def run_nmap_scan(ip):
    result = subprocess.run([NMAP_PATH, "-sV", "-T4", "-oX", "-", ip], capture_output=True, text=True)
    return result.stdout

# ----------------------------
# Save triage report
# ----------------------------
def save_report(incident_id, data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{OUTPUT_DIR}/{incident_id}_report.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved triage report: {filename}")

# ----------------------------
# Incident triage
# ----------------------------
def triage_incident(alert_id, time, entity, domain=None):
    print(f"\n[!] Triage for Alert ID: {alert_id}")
    report = {
        "alert_id": alert_id,
        "timestamp": time,
        "entity": entity,
        "domain": domain,
        "enrichment": {},
        "nmap_scan": ""
    }

    try:
        print(" > AbuseIPDB lookup...")
        report["enrichment"]["abuseipdb"] = abuseipdb_lookup(entity)
    except Exception as e:
        report["enrichment"]["abuseipdb"] = {"error": str(e)}

    if domain:
        try:
            print(" > VirusTotal domain lookup...")
            report["enrichment"]["virustotal"] = virustotal_lookup(domain)
        except Exception as e:
            report["enrichment"]["virustotal"] = {"error": str(e)}

    try:
        print(" > Running nmap on host...")
        report["nmap_scan"] = run_nmap_scan(entity)
    except Exception as e:
        report["nmap_scan"] = f"Error: {e}"

    save_report(alert_id, report)

# ----------------------------
# MAIN WORKFLOW
# ----------------------------
def main():
    token = get_azure_token()
    alerts = get_sentinel_alerts(token)
    
    for alert in alerts:
        time, alert_id, name, entity, entities_raw = alert
        domain = None

        # Optional: extract domain if present
        if isinstance(entities_raw, str) and "DnsDomain" in entities_raw:
            try:
                entities = json.loads(entities_raw)
                for item in entities:
                    if item.get("Type") == "dns":
                        domain = item.get("Address")
            except Exception:
                pass

        triage_incident(alert_id, time, entity, domain)

if __name__ == "__main__":
    main()