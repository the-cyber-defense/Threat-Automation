# Requires: AzureAD and Microsoft.Graph modules
# Connect to MS Graph with required permissions


Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "Directory.Read.All", "User.Read.All"

# Set variables
$UserPrincipalName = "alice@example.com"
$RoleName = "Privileged Role Administrator"
$TenantId = (Get-MgContext).TenantId

# Get directory roles and filter by name
$roles = Get-MgRoleManagementDirectoryRoleDefinition -Filter "displayName eq '$RoleName'"
$roleId = $roles.Id

# Get user
$user = Get-MgUser -UserId $UserPrincipalName

# Activate role (simulate)
Write-Output "Activating role '$RoleName' for user '$UserPrincipalName'..."
$activationTime = Get-Date
$expiry = $activationTime.AddHours(4)

# Simulate activation log
$log = @{
    User = $UserPrincipalName
    Role = $RoleName
    Activated = $true
    ActivationTime = $activationTime
    ExpiresAt = $expiry
}

# Output log
$log | ConvertTo-Json | Out-File "./PIM-Activation-Log-$($activationTime.ToString('yyyyMMdd-HHmm')).json"

# Notify via Teams webhook or email (stubbed)
Write-Output "Notifying security team: $UserPrincipalName has activated $RoleName until $($expiry)..."