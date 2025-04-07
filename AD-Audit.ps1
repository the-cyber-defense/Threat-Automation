### 📜 `AD-Audit.ps1`
```powershell
param (
    [string]$OutputPath = "AD_Audit_Report.csv"
)

Import-Module ActiveDirectory

# Get all users
$users = Get-ADUser -Filter * -Properties DisplayName, LastLogonDate, Enabled, MemberOf

# Find Domain Admins
$domainAdmins = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName

# Build report
$report = foreach ($user in $users) {
    [PSCustomObject]@{
        Username       = $user.SamAccountName
        DisplayName    = $user.DisplayName
        Enabled        = $user.Enabled
        LastLogon      = $user.LastLogonDate
        IsPrivileged   = if ($domainAdmins -contains $user.SamAccountName) { "Yes" } else { "No" }
        GroupCount     = ($user.MemberOf).Count
    }
}

# Export
$report | Sort-Object IsPrivileged -Descending | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Output "Audit complete. Report saved to $OutputPath"