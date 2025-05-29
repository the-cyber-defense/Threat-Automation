# Script 2: Create a Baseline Conditional Access Policy (Terraform)
# File: main.tf

terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.30" # Use a recent version
    }
  }
}

provider "azuread" {
  # Configuration options if not using Azure CLI login context
  # tenant_id = "YOUR_TENANT_ID"
  # client_id = "YOUR_CLIENT_ID" (for Service Principal)
  # client_secret = "YOUR_CLIENT_SECRET" (for Service Principal)
}

# Data source to get built-in Administrator roles
data "azuread_directory_roles" "admin_roles" {
  names = [
    "Global Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Privileged Role Administrator"
    # Add other admin roles as needed
  ]
}

resource "azuread_conditional_access_policy" "admin_mfa_policy" {
  display_name = "CA001: Require MFA for Administrators"
  state        = "enabled" # Can be "enabled", "disabled", or "enabledForReportingButNotEnforced"

  conditions {
    users {
      # Include users assigned to the specified directory roles
      included_users = ["All"] # Start broad, then refine with role_ids
      # OR include specific role template IDs:
      # included_user_roles = [ for role in data.azuread_directory_roles.admin_roles.objects : role.template_id ]
      
      # Example using specific role template IDs (safer than "All" for admin roles)
      # You'd get these template IDs from Azure AD documentation or by querying the API
      # "Global Administrator" -> "62e90394-69f5-4237-9190-012177145e10"
      # "Security Administrator" -> "194ae4cb-b126-40b2-bd5b-6091b380977d"
      included_user_roles = [
        "62e90394-69f5-4237-9190-012177145e10", # Global Admin
        "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Admin
        # Add more role template IDs
      ]

      # Exclude emergency access / break-glass accounts
      excluded_users = [
        # "user_principal_name_of_breakglass1@yourdomain.com",
        # "user_principal_name_of_breakglass2@yourdomain.com"
        # For actual IDs: data.azuread_user.break_glass.object_id
      ]
    }

    applications {
      included_applications = ["All"] # All cloud apps
      excluded_applications = []
    }

    client_app_types = ["all"] # Includes browser, mobile apps, desktop clients

    # Optional: Add location or device platform conditions
    # sign_in_risk_levels = ["high", "medium"]
  }

  grant_controls {
    operator = "OR"
    built_in_controls = ["mfa"] # Require Multi-Factor Authentication
    # terms_of_use = []
  }

  session_controls {
    # empty by default
  }
}

# Output policy ID
output "admin_mfa_policy_id" {
  value = azuread_conditional_access_policy.admin_mfa_policy.id
}