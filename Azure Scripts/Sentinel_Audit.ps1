param (
    [Parameter(Mandatory=$false)] [string]$LogFolder = "C:\Audit"
)

# Ensure folder exists
New-Item -ItemType Directory -Path $LogFolder -Force | Out-Null

# Function definitions (same as above)
# ...

# Final Execution
Get-EntraIDSignInLogs
Run-DefenderScan
Get-SecurityEvents
Get-GroupMembershipChanges
Get-DeviceHealthSummary

# Optional: Return summary result
$result = [PSCustomObject]@{
    Status = "Completed"
    Timestamp = (Get-Date)
    Folder = $LogFolder
}
return $result | ConvertTo-Json

### refer to Sentinel Playbook to setup LogicAPP