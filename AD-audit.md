# PowerShell AD Audit

This script generates an audit report of Active Directory users, highlighting privileged accounts, last logon times, and account status. Useful for security audits, compliance checks, and access reviews.

## Features
- Lists all users and their group memberships
- Identifies Domain Admins and other privileged accounts
- Reports last logon time, enabled/disabled status
- Exports to CSV for audit tracking

## Requirements
- Run on a domain-joined machine with Active Directory PowerShell module
- PowerShell 5.1+

## Usage
```powershell
.\AD-Audit.ps1 -OutputPath "C:\Reports\AD_Audit.csv"