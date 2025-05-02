###  AD-Audit.ps1 ###
<#
.Overview
   This script audits Azure infrastructure and Azure AD for common security vulnerabilities using Az and Microsoft Graph.

.DESCRIPTION
    This script performs two sets of audits:
      1. It loops through your Azure subscriptions to identify common resource misconfigurations such as NSG rules that allow inbound traffic from any source.
      2. It connects to Microsoft Graph to retrieve key Azure AD security details, including an audit of user authentication methods and Conditional Access policies.
    Audit findings are consolidated into a CSV report.

.PARAMETER OutputPath
    The path to save the final CSV audit report.

.EXAMPLE
    .\Integrated_Azure_Audit.ps1 -OutputPath "C:\Reports\Integrated_Audit_Report.csv"
#>

param (
    [string]$OutputPath = "Integrated_Audit_Report.csv"
)

### PART 1: Prepare and Connect ###

# Import required modules for Azure management
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Import-Module Az.Network -ErrorAction Stop
} catch {
    Write-Error "One or more Az modules are missing. Please install the Az module using 'Install-Module Az -AllowClobber -Force'."
    exit 1
}

# Import Microsoft Graph module
try {
    Import-Module Microsoft.Graph -ErrorAction Stop
} catch {
    Write-Error "Microsoft.Graph module is not installed. Install it with 'Install-Module Microsoft.Graph -AllowClobber -Force'."
    exit 1
}

# Connect to Azure
try {
    Write-Output "Connecting to Azure account..."
    Connect-AzAccount -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to your Azure account. Check your credentials and network connection."
    exit 1
}

# Connect to Microsoft Graph with required scopes.
# Ensure you have consented to scopes: User.Read.All, Group.Read.All, Policy.Read.All, Directory.Read.All.
try {
    Write-Output "Connecting to Microsoft Graph..."
    Connect-MgGraph -Scopes "User.Read.All","Group.Read.All","Policy.Read.All","Directory.Read.All" -ErrorAction Stop
} catch {
    Write-Error "Failed to connect to Microsoft Graph. Please check your configuration."
    exit 1
}

### PART 2: Audit Azure Resources ###

$azureReport = @()

# Get all Azure subscriptions
$subscriptions = Get-AzSubscription

foreach ($subscription in $subscriptions) {
    Write-Output "Processing subscription: $($subscription.Name)"
    Set-AzContext -Subscription $subscription.Id

    # --- NSG Checks ---
    try {
        $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve NSGs in subscription $($subscription.Name). Skipping NSG checks."
        continue
    }
    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            if ($rule.Direction -eq "Inbound" -and 
                $rule.Access -eq "Allow" -and 
                ($rule.SourceAddressPrefix -eq "0.0.0.0/0" -or $rule.SourceAddressPrefix -eq "*")) {
                
                $azureReport += [PSCustomObject]@{
                    Subscription   = $subscription.Name
                    ResourceGroup  = $nsg.ResourceGroupName
                    ResourceType   = "NetworkSecurityGroup"
                    ResourceName   = $nsg.Name
                    Vulnerability  = "NSG rule allowing inbound traffic from any source"
                    Details        = "Rule: $($rule.Name), Priority: $($rule.Priority), Port: $($rule.DestinationPortRange)"
                }
            }
        }
    }

    # --- Generic Public Access Checks ---
    try {
        $resources = Get-AzResource -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not retrieve resources in subscription $($subscription.Name). Skipping public access checks."
        continue
    }
    foreach ($res in $resources) {
        # This example check looks for "PublicAccess" in resource properties.
        if ($res.Properties -and ($res.Properties | Out-String) -match "PublicAccess") {
            $azureReport += [PSCustomObject]@{
                Subscription   = $subscription.Name
                ResourceGroup  = $res.ResourceGroupName
                ResourceType   = $res.ResourceType
                ResourceName   = $res.Name
                Vulnerability  = "Potential Public Access Misconfiguration"
                Details        = "Review 'PublicAccess' settings for this resource."
            }
        }
    }
}

### PART 3: Audit Azure AD via Microsoft Graph ###

$aadReport = @()

# --- Retrieve Users and Analyze Authentication Methods ---
Write-Output "Retrieving Azure AD users..."
try {
    $aadUsers = Get-MgUser -All -ErrorAction Stop
} catch {
    Write-Warning "Failed to retrieve Azure AD users via Microsoft Graph."
    $aadUsers = @()
}

foreach ($user in $aadUsers) {
    $userUPN = $user.UserPrincipalName
    # Attempt to retrieve a list of authentication methods.
    # This is a lightweight check to see if the user has any registered authentication methods beyond the default password.
    $authMethods = @()
    try {
        # This command gathers all authentication methods registered for the user.
        $authMethods = (Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction Stop) 
    } catch {
        # In many cases this call might not return anything if no extra methods are registered.
        $authMethods = @()
    }
    
    # A simple check: if no additional authentication methods are found,
    # then the user might not have configured MFA or alternative strong auth.
    if ($authMethods.Count -eq 0) {
        $aadReport += [PSCustomObject]@{
            Subscription   = "Azure AD"
            ResourceGroup  = "N/A"
            ResourceType   = "UserAccount"
            ResourceName   = $userUPN
            Vulnerability  = "No registered additional authentication methods"
            Details        = "User may be missing MFA or alternative strong authentication method."
        }
    }
}

# --- Retrieve Conditional Access Policies ---
Write-Output "Retrieving Conditional Access policies..."
try {
    $caPolicies = Get-MgConditionalAccessPolicy -ErrorAction Stop
} catch {
    Write-Warning "Failed to retrieve Conditional Access policies."
    $caPolicies = @()
}

foreach ($policy in $caPolicies) {
    # Example check: report any CA policy that is disabled or not enforcing MFA.
    if ($policy.State -ne "enabled") {
        $aadReport += [PSCustomObject]@{
            Subscription   = "Azure AD"
            ResourceGroup  = "N/A"
            ResourceType   = "ConditionalAccessPolicy"
            ResourceName   = $policy.DisplayName
            Vulnerability  = "Conditional Access Policy not enabled"
            Details        = "Policy is in state '$($policy.State)'. Review if this is intended."
        }
    } elseif ($policy.GrantControls -and $policy.GrantControls.Mfa) {
        # If MFA is required this check passes; if not, you could add a condition.
        # For illustration purposes, we assume that absence of the MFA control flag might indicate a misconfiguration.
        # (Note: In real-world scenarios, evaluate the full grant controls requirements.)
        # Optionally add more granular checks here.
        continue
    } else {
        # If the policy is enabled but does not enforce MFA in any way, flag it.
        $aadReport += [PSCustomObject]@{
            Subscription   = "Azure AD"
            ResourceGroup  = "N/A"
            ResourceType   = "ConditionalAccessPolicy"
            ResourceName   = $policy.DisplayName
            Vulnerability  = "Conditional Access Policy may not enforce MFA"
            Details        = "Review the grant controls for MFA enforcement in this policy."
        }
    }
}

### PART 4: Consolidate and Export the Audit Report ###

$finalReport = $azureReport + $aadReport

try {
    $finalReport | Sort-Object Subscription, ResourceType | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Output "Audit complete. Report saved to $OutputPath"
} catch {
    Write-Error "Failed to write the report to $OutputPath"
}
