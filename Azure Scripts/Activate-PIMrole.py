import json
import datetime
import requests

# Simulated activation inputs
user_principal_name = "alice@example.com"
role_name = "Privileged Role Administrator"
activation_time = datetime.datetime.now()
expiry = activation_time + datetime.timedelta(hours=4)

# Log format
log_entry = {
    "User": user_principal_name,
    "Role": role_name,
    "Activated": True,
    "ActivationTime": activation_time.isoformat(),
    "ExpiresAt": expiry.isoformat()
}

# Save log locally
log_filename = f"PIM_Activation_Log_{activation_time.strftime('%Y%m%d-%H%M')}.json"
with open(log_filename, "w") as f:
    json.dump(log_entry, f, indent=2)

print(f"✅ Role '{role_name}' activated for '{user_principal_name}' until {expiry}")
print(f"📁 Log saved to {log_filename}")

# --- Notification stub (example Teams webhook) ---
# webhook_url = "https://your-teams-webhook-url"
# message = {
#     "@type": "MessageCard",
#     "@context": "http://schema.org/extensions",
#     "summary": f"PIM Role Activation",
#     "themeColor": "0076D7",
#     "title": "Azure PIM Role Activated",
#     "text": f"**{user_principal_name}** activated **{role_name}** until **{expiry.strftime('%Y-%m-%d %H:%M')}**"
# }
# requests.post(webhook_url, json=message)