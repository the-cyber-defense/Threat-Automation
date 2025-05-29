import requests
import pandas as pd
import datetime
import json
import os

# --- Simulated sync health data (replace with real API or log ingestion) ---
sync_status = [
    {
        "domainController": "dc1.corp.local",
        "syncStatus": "Healthy",
        "lastSync": "2025-05-28T05:00:00",
        "objectsWithErrors": 2,
        "orphanedObjects": 1
    },
    {
        "domainController": "dc2.corp.local",
        "syncStatus": "Warning",
        "lastSync": "2025-05-28T04:45:00",
        "objectsWithErrors": 15,
        "orphanedObjects": 7
    },
    {
        "domainController": "dc3.corp.local",
        "syncStatus": "Error",
        "lastSync": "2025-05-28T03:00:00",
        "objectsWithErrors": 33,
        "orphanedObjects": 12
    }
]

# --- Convert to DataFrame and save ---
df = pd.DataFrame(sync_status)
timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
csv_file = f"ad_connect_sync_health_{timestamp}.csv"
df.to_csv(csv_file, index=False)

print(f"✅ Sync health report generated: {csv_file}")

# --- Detect issues and flag errors ---
issues = df[df["syncStatus"] != "Healthy"]
if not issues.empty:
    print("⚠️ Detected sync issues on the following domain controllers:")
    print(issues[["domainController", "syncStatus", "objectsWithErrors", "orphanedObjects"]])

# --- Notify via Microsoft Teams Webhook (optional) ---
# webhook_url = "https://your-teams-webhook-url"
# message = {
#     "@type": "MessageCard",
#     "@context": "http://schema.org/extensions",
#     "themeColor": "FF0000",
#     "summary": "Azure AD Connect Sync Issue Detected",
#     "title": "Azure AD Connect Sync Health Alert",
#     "text": f"Detected sync warnings or errors on the following domain controllers:\n\n```{issues.to_string(index=False)}```",
# }
# requests.post(webhook_url, json=message)