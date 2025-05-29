# Script 1: Activate PIM Role Eligibility with Justification (PowerShell & MS Graph API)

#Requires -Module Microsoft.Graph.Identity.SignIns
#Requires -Module Microsoft.Graph.DeviceManagement.Enforcement # For Conditional Access PIM activation

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory", "Directory.Read.All"

# --- Parameters ---
$roleDefinitionName = "Global Administrator" # Or "Security Administrator", "User Administrator", etc.
$justification = "Performing scheduled maintenance on critical system X (INC12345)"
$durationHours = 2 # How long the role should be active (PIM policy might limit this)

# --- Script Logic ---

# 1. Get current user's ID
try {
    $currentUser = Get-MgContext
    $userId = $currentUser.Account.Id
    Write-Host "Current User ID: $userId"
}
catch {
    Write-Error "Failed to get current user context. Ensure you are connected via Connect-MgGraph."
    exit 1
}

# 2. Find the Role Definition ID for the given role name
try {
    $roleDefinition = Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$roleDefinitionName'" | Select-Object -First 1
    if (-not $roleDefinition) {
        Write-Error "Role definition '$roleDefinitionName' not found."
        exit 1
    }
    $roleDefinitionId = $roleDefinition.Id
    Write-Host "Role Definition ID for '$roleDefinitionName': $roleDefinitionId"
}
catch {
    Write-Error "Failed to find role definition '$roleDefinitionName'. Error: $($_.Exception.Message)"
    exit 1
}

# 3. Find the user's eligible assignment for this role
try {
    $eligibleAssignment = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "PrincipalId eq '$userId' and RoleDefinitionId eq '$roleDefinitionId'" | Where-Object {$_.EligibilityScheduleId -ne $null} | Select-Object -First 1
    if (-not $eligibleAssignment) {
        Write-Error "No eligible assignment found for user '$($currentUser.Account.DisplayName)' for role '$roleDefinitionName'."
        exit 1
    }
    Write-Host "Found eligible assignment: $($eligibleAssignment.Id)"
}
catch {
    Write-Error "Failed to fetch eligible assignments. Error: $($_.Exception.Message)"
    exit 1
}

# 4. Prepare the activation request
$scheduleInfo = New-Object Microsoft.Graph.PowerShell.Models.MicrosoftGraphRequestSchedule
$scheduleInfo.StartDateTime = (Get-Date).ToUniversalTime().ToString("o")
$scheduleInfo.Expiration = New-Object Microsoft.Graph.PowerShell.Models.MicrosoftGraphExpirationPattern
$scheduleInfo.Expiration.Type = "afterDuration"
$scheduleInfo.Expiration.Duration = "PT$($durationHours)H" # PT2H for 2 hours

$activationParams = @{
    PrincipalId = $userId
    RoleDefinitionId = $roleDefinitionId
    DirectoryScopeId = "/" # Root scope, typically what you want for directory roles
    Justification = $justification
    ScheduleInfo = $scheduleInfo
    Action = "selfActivate" # For self-activation
    # TicketInfo = @{ # Optional ticket info
    #     TicketNumber = "INC12345"
    #     TicketSystem = "ServiceNow"
    # }
}

# 5. Activate the role
try {
    Write-Host "Attempting to activate role '$roleDefinitionName'..."
    $activationRequest = New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $activationParams
    Write-Host "Role activation request submitted. Status: $($activationRequest.Status)"
    Write-Host "Activated Role Instance ID: $($activationRequest.Id)"
    Write-Host "You might need to sign out and sign back in for the role to take full effect in all portals."
}
catch {
    Write-Error "Failed to activate PIM role. Error: $($_.Exception.Message)"
    # You might want to parse the error for more details, e.g., MFA required by PIM policy
    # $errorDetails = $_.Exception.Response.Content | ConvertFrom-Json
    # Write-Warning "Error details: $($errorDetails.error.message)"
    exit 1
}

Disconnect-MgGraph