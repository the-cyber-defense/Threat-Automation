# Query Log Analytics for Suspicious Sign-ins (KQL via PowerShell)

# --- Parameters ---
$workspaceId = "YOUR_LOG_ANALYTICS_WORKSPACE_ID" # e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
$resourceGroupName = "YOUR_LOG_ANALYTICS_RESOURCE_GROUP"
$timeRangeHours = 24 # How far back to search

# --- Script Logic ---

# 1. Connect to Azure
try {
    Connect-AzAccount -ErrorAction Stop
}
catch {
    Write-Error "Failed to connect to Azure. Please run Connect-AzAccount manually."
    exit 1
}

# 2. Define the KQL Query
# This query looks for failed sign-ins from distinct IP addresses for a specific user
# or multiple failed sign-ins from non-corporate IPs
# Adapt this query for your specific needs and data (e.g., MDI alerts in SecurityAlert table)

$kqlQuery = @"
SigninLogs
| where TimeGenerated > ago($(($timeRangeHours))h)
| where ResultType != 0 // Failed sign-ins (AADSTS error codes)
| summarize FailureCount = count(),
            DistinctIPs = dcount(IPAddress),
            TargetUser = take_any(UserPrincipalName),
            LastFailureTime = max(TimeGenerated),
            ErrorCodes = make_set(ResultType),
            Locations = make_set(Location)
            by IPAddress, AppDisplayName
| where FailureCount > 5 // Arbitrary threshold for multiple failures from one IP
| project LastFailureTime, TargetUser, IPAddress, FailureCount, Locations, ErrorCodes, AppDisplayName
| order by LastFailureTime desc
"@

# Example KQL for Defender for Identity related alerts (if using Sentinel - SecurityAlert table)
# $kqlQuery_MDI = @"
# SecurityAlert
# | where TimeGenerated > ago($(($timeRangeHours))h)
# | where ProviderName == "Azure Advanced Threat Protection" // Or "MDATP" if from Defender for Endpoint
# // | where AlertName contains "password spray" or AlertName contains "brute force"
# | sort by TimeGenerated desc
# | project TimeGenerated, AlertName, CompromisedEntity, Entities, Description
# "@
# Choose one query or combine logic

Write-Host "Executing KQL Query in Log Analytics Workspace: $workspaceId"
Write-Host "Query: $kqlQuery"

# 3. Execute the query
try {
    $queryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $kqlQuery -ErrorAction Stop
    # For newer Az.Monitor module which includes Invoke-AzOperationalInsightsQuery:
    # Or using older (Az.OperationalInsights): Get-AzOperationalInsightsSearchResults -WorkspaceId $workspaceId -Query $kqlQuery

    if ($queryResults.Results.Count -gt 0) {
        Write-Host "Suspicious sign-in activities found:" -ForegroundColor Yellow
        $queryResults.Results | Format-Table
    }
    else {
        Write-Host "No suspicious sign-in activities matching the KQL query found in the last $($timeRangeHours) hours." -ForegroundColor Green
    }
}
catch {
    Write-Error "Failed to execute KQL query. Error: $($_.Exception.Message)"
    # Check if the table 'SigninLogs' or 'SecurityAlert' exists or has data.
    exit 1
}
