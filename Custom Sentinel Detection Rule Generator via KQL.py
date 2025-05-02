

# install requirements using bash pip install azure-identity requests


import uuid
import requests
from azure.identity import DefaultAzureCredential

# === Config ===
subscription_id = "YOUR_SUBSCRIPTION_ID"
resource_group = "YOUR_RESOURCE_GROUP"
workspace_name = "YOUR_SENTINEL_WORKSPACE"
rule_name = "Suspicious PowerShell Use"
kql_query = """
SecurityEvent
| where EventID == 4688 and NewProcessName endswith "powershell.exe"
| where CommandLine has "-enc" or CommandLine has "-nop"
| project TimeGenerated, Computer, Account, CommandLine
"""

# === Auth ===
credential = DefaultAzureCredential()
token = credential.get_token("https://management.azure.com/.default").token
headers = {
    "Authorization": f"Bearer {token}",
    "Content-Type": "application/json"
}

# === Rule Body ===
rule_id = str(uuid.uuid4())
url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/alertRules/{rule_id}?api-version=2023-02-01-preview"

rule_payload = {
    "kind": "Scheduled",
    "properties": {
        "displayName": rule_name,
        "enabled": True,
        "severity": "Medium",
        "query": kql_query,
        "queryFrequency": "PT1H",
        "queryPeriod": "PT1H",
        "triggerOperator": "GreaterThan",
        "triggerThreshold": 0,
        "suppressionDuration": "PT1H",
        "suppressionEnabled": False,
        "tactics": ["Execution"],
        "alertRuleTemplateName": None,
        "incidentConfiguration": {
            "createIncident": True
        }
    }
}

# === Create Rule ===
response = requests.put(url, headers=headers, json=rule_payload)
if response.status_code == 200 or response.status_code == 201:
    print("Detection rule created successfully!")
else:
    print(f"Failed: {response.status_code}\n{response.text}")