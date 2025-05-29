Directly interacts with Azure AD for user lifecycle management.
Automates PIM eligibility assignment, a key Azure security best practice (Just-In-Time access).

###Save the code as identity_automation.go.
Set the environment variables:
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-app-client-id"
export AZURE_CLIENT_SECRET="your-app-client-secret"
# Optional, for legacy system part:
export MOCK_LEGACY_API_ENDPOINT="https://your-chosen-mock-api.com/somepath"
# Optional for UPN domain (adjust if needed):
export USERDOMAIN="YOUR_TENANT.onmicrosoft.com" # or your custom domain
Run the script:
go run identity_automation.go ###

Makes HTTP requests to MS Graph API
Handles OAUTH2 client cred. flows
Marshals Go structs to JSON for request bodies
Unmarashals JSONS responses
Simulates integration with a legacy system api


Uses environment variables for sensitive data (os.Getenv)