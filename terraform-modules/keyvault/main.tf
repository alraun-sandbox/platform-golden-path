/**
 * Key Vault for application secrets and the claims data encryption key.
 *
 * RBAC authorization rather than access policies, because access policies cannot be reviewed
 * at scale and cannot be granted just-in-time.
 */

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "key_vault_name" { type = string }
variable "tags" { type = map(string) }
variable "tenant_id" { type = string }
variable "private_endpoint_subnet_id" { type = string }
variable "private_dns_zone_id" { type = string }

variable "purge_protection_enabled" {
  description = "Off in dev so the environment can be torn down and rebuilt; on everywhere else."
  type        = bool
  default     = false
}

variable "allowed_ip_rules" {
  description = "Break-glass IP allow list. Empty is the correct value."
  type        = list(string)
  default     = []
}

resource "azurerm_key_vault" "this" {
  name                = var.key_vault_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tenant_id           = var.tenant_id
  sku_name            = "standard"
  tags                = var.tags

  rbac_authorization_enabled = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = var.purge_protection_enabled
  # Policy ZUR-SEC-001.
  public_network_access_enabled = false

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
    ip_rules       = var.allowed_ip_rules
  }
}

resource "azurerm_private_endpoint" "this" {
  name                = "pe-${var.key_vault_name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-${var.key_vault_name}"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [var.private_dns_zone_id]
  }
}

output "key_vault_id" { value = azurerm_key_vault.this.id }
output "key_vault_uri" { value = azurerm_key_vault.this.vault_uri }
output "key_vault_name" { value = azurerm_key_vault.this.name }
