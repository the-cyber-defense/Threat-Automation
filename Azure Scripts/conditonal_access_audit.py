import requests
import pandas as pd
from datetime import datetime
from msal import ConfidentialClientApplication

# --- Config ---
TENANT_ID = "your-tenant-id"
CLIENT_ID = "your-client-id"
CLIENT_SECRET = "your-client-secret"

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# --- Authenticate ---
def get_token():
    app = ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY, client_credential=CLIENT_SECRET
    )
    token_result = app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" in token_result:
        return token_result["access_token"]
    else:
        raise Exception("Token acquisition failed: ", token_result.get("error_description"))

# --- Fetch Policies ---
def fetch_conditional_access_policies(token):
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(GRAPH_ENDPOINT, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch policies: {response.text}")
    return response.json().get("value", [])

# --- Simulate KQL Usage (Stub) ---
def simulate_kql_usage():
    return {
        "MFA for Admins": 58,
        "Block Legacy Auth": 132,
        "Test Policy": 0,
    }

# --- Generate Report ---
def generate_audit_report(policies, usage_data):
    rows = []
    for policy in policies:
        name = policy.get("displayName", "Unnamed")
        state = policy.get("state", "unknown")
        mfa_required = "mfa" in policy.get("grantControls", {}).get("builtInControls", [])
        usage_count = usage_data.get(name, 0)

        rows.append({
            "Policy Name": name,
            "Status": state,
            "MFA Required": mfa_required,
            "Usage (Last 30d)": usage_count
        })

    df = pd.DataFrame(rows)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"conditional_access_audit_report_{timestamp}.csv"
    df.to_csv(filename, index=False)
    print(f"✅ Report saved: {filename}")
    return df

# --- Main Execution ---
if __name__ == "__main__":
    print("🔐 Authenticating with Microsoft Graph...")
    token = get_token()
    
    print("📡 Fetching Conditional Access Policies...")
    policies = fetch_conditional_access_policies(token)
    
    print("📊 Simulating policy usage data...")
    usage_data = simulate_kql_usage()
    
    print("📁 Generating audit report...")
    generate_audit_report(policies, usage_data)