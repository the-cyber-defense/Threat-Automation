import os
import json
import requests
import subprocess
from datetime import datetime
from msal import ConfidentialClientApplication
from requests.auth import HTTPBasicAuth

# ----------------------------
# CONFIGURATION
# ----------------------------
# Azure Sentinel
TENANT_ID = "your_tenant_id"
CLIENT_ID = "your_client_id"
CLIENT_SECRET = "your_client_secret"
WORKSPACE_ID = "your_workspace_id"

# Threat Intelligence APIs
ABUSEIPDB_API_KEY = "your_abuseipdb_key"
VT_API_KEY = "your_virustotal_key"

# Nmap binary path
NMAP_PATH = "nmap"

# Local output
OUTPUT_DIR = "incident_reports"

# Jira Configuration
JIRA_URL = "https://your-domain.atlassian.net"
JIRA_USER = "your_email@example.com"
JIRA_API_TOKEN = "your_api_token"
JIRA_PROJECT_KEY = "SOC"  # or your Jira project key

# ----------------------------
# Sentinel Token Auth
# ----------------------------
def get_azure_token():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = ConfidentialClientApplication(CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET)
    token = app.acquire_token_for_client(scopes=["https://api.loganalytics.io/.default"])
    return token["access_token"]

# ----------------------------
# Sentinel Alert Query
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
# Threat Intelligence
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

# ----------------------------
# Vulnerability Scan
# ----------------------------
def run_nmap_scan(ip):
    result = subprocess.run([NMAP_PATH, "-sV", "-T4", "-oX", "-", ip], capture_output=True, text=True)
    return result.stdout

# ----------------------------
# Report Writer
# ----------------------------
def save_report(incident_id, data):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = f"{OUTPUT_DIR}/{incident_id}_report.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved triage report: {filename}")
    return filename

# ----------------------------
# Jira Integration
# ----------------------------
def create_jira_ticket(alert_id, entity, report_path, severity="Medium", summary="Automated triage completed"):
    issue_url = f"{JIRA_URL}/rest/api/3/issue"
    auth = HTTPBasicAuth(JIRA_USER, JIRA_API_TOKEN)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    description = f"""
    *Automated Triage Report*
    - Alert ID: {alert_id}
    - Entity: {entity}
    - Severity: {severity}
    - Report Path: {report_path}
    - Triage Time: {datetime.utcnow().isoformat()}

    _Full JSON report available locally for further investigation._
    """

    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"Automated Incident Triage - {alert_id}",
            "description": description,
            "issuetype": {"name": "Task"},
            "priority": {"name": severity}
        }
    }

    try:
        response = requests.post(issue_url, json=payload, headers=headers, auth=auth)
        if response.status_code == 201:
            print(f"[+] Jira ticket created: {response.json()['key']}")
        else:
            print(f"[-] Jira error: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[-] Jira ticket creation failed: {e}")

# ----------------------------
# Incident Triage Logic
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
        print(" > Enriching with AbuseIPDB...")
        report["enrichment"]["abuseipdb"] = abuseipdb_lookup(entity)
    except Exception as e:
        report["enrichment"]["abuseipdb"] = {"error": str(e)}

    if domain:
        try:
            print(" > Enriching with VirusTotal...")
            report["enrichment"]["virustotal"] = virustotal_lookup(domain)
        except Exception as e:
            report["enrichment"]["virustotal"] = {"error": str(e)}

    try:
        print(" > Running Nmap scan...")
        report["nmap_scan"] = run_nmap_scan(entity)
    except Exception as e:
        report["nmap_scan"] = f"Error: {e}"

    report_path = save_report(alert_id, report)
    create_jira_ticket(alert_id, entity, report_path)

# ----------------------------
# Main Workflow
# ----------------------------
def main():
    token = get_azure_token()
    alerts = get_sentinel_alerts(token)

    for alert in alerts:
        time, alert_id, name, entity, entities_raw = alert
        domain = None

        # Optional domain extraction
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