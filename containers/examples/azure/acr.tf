# Azure Container Registry hardened for the pipeline, plus a user-assigned
# managed identity that GitHub Actions uses through OIDC (federated credential)
# to push. No client secret is created anywhere.

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  features {}
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "eastus"
}

variable "resource_group_name" {
  description = "Resource group for the registry and identity"
  type        = string
  default     = "rg-acme-containers"
}

variable "registry_name" {
  description = "Globally unique ACR name (alphanumeric only)"
  type        = string
  default     = "acmecontainers"
}

variable "github_repo" {
  description = "owner/repo allowed to push, e.g. acme/api"
  type        = string
  default     = "acme/api"
}

variable "ci_egress_ips" {
  description = "CIDRs allowed to reach the registry over the public endpoint (CI egress). Empty = public access off; use a private endpoint instead."
  type        = list(string)
  default     = []
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "containers" {
  name     = var.resource_group_name
  location = var.location
}

# --- registry ---------------------------------------------------------------

resource "azurerm_container_registry" "app" {
  name                = var.registry_name
  resource_group_name = azurerm_resource_group.containers.name
  location            = azurerm_resource_group.containers.location
  sku                 = "Premium" # retention, private link, network rules need Premium

  admin_enabled          = false # the shared admin credential is the most-leaked secret in Azure
  anonymous_pull_enabled = false
  export_policy_enabled  = false # images cannot be exported to another registry
  data_endpoint_enabled  = true  # stable data endpoints for firewall allow-lists

  public_network_access_enabled = length(var.ci_egress_ips) > 0
  network_rule_bypass_option    = "AzureServices" # Defender scanning and other trusted services

  dynamic "network_rule_set" {
    for_each = length(var.ci_egress_ips) > 0 ? [1] : []
    content {
      default_action = "Deny"
      dynamic "ip_rule" {
        for_each = var.ci_egress_ips
        content {
          action   = "Allow"
          ip_range = ip_rule.value
        }
      }
    }
  }

  retention_policy_in_days = 7 # untagged manifests are deleted after 7 days

  identity {
    type = "SystemAssigned"
  }

  tags = { managed-by = "terraform" }
}

# --- identity GitHub Actions uses through OIDC --------------------------------

resource "azurerm_user_assigned_identity" "github_push" {
  name                = "id-github-push-${replace(var.github_repo, "/", "-")}"
  resource_group_name = azurerm_resource_group.containers.name
  location            = azurerm_resource_group.containers.location
}

# Only the main branch of the named repo can exchange its OIDC token for this identity.
resource "azurerm_federated_identity_credential" "github_main" {
  name                = "github-${replace(var.github_repo, "/", "-")}-main"
  resource_group_name = azurerm_resource_group.containers.name
  parent_id           = azurerm_user_assigned_identity.github_push.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:${var.github_repo}:ref:refs/heads/main"
}

resource "azurerm_role_assignment" "github_acr_push" {
  scope                = azurerm_container_registry.app.id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.github_push.principal_id
}

# Run Command on the Docker VMs: Virtual Machine Contributor is broader than
# needed; a custom role with Microsoft.Compute/virtualMachines/runCommand/action
# on the VM resource group is the tighter option.
resource "azurerm_role_assignment" "github_run_command" {
  scope                = azurerm_resource_group.containers.id
  role_definition_name = "Virtual Machine Contributor"
  principal_id         = azurerm_user_assigned_identity.github_push.principal_id
}

# --- outputs ----------------------------------------------------------------

output "login_server" {
  value       = azurerm_container_registry.app.login_server
  description = "Registry host for the workflow IMAGE value"
}

output "client_id" {
  value       = azurerm_user_assigned_identity.github_push.client_id
  description = "GitHub secret AZURE_CLIENT_ID"
}

output "tenant_id" {
  value       = data.azurerm_client_config.current.tenant_id
  description = "GitHub secret AZURE_TENANT_ID"
}

output "subscription_id" {
  value       = data.azurerm_client_config.current.subscription_id
  description = "GitHub secret AZURE_SUBSCRIPTION_ID"
}
