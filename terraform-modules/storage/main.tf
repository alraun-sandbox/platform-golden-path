/**
 * Storage for claim documents - photographs of hail damage, loss adjuster reports, invoices.
 *
 * Some of the most sensitive material in the estate, and the single most common source of
 * public data exposure in the industry. Hence: private endpoint, deny by default, no public
 * blob access, no anonymous containers, TLS 1.2, infrastructure encryption.
 *
 * Scenario "public storage" in the flaw catalogue is a pull request that flips
 * allow_nested_items_to_be_public to true. Policy ZUR-SEC-001 denies it, and the reviewer
 * sees the reason in the pull request comment rather than a red X.
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
variable "storage_account_name" { type = string }
variable "tags" { type = map(string) }
variable "private_endpoint_subnet_id" { type = string }
variable "private_dns_zone_id" { type = string }

variable "containers" {
  type    = list(string)
  default = ["claim-documents", "claim-photos", "adjuster-reports"]
}

variable "replication_type" {
  type    = string
  default = "ZRS"
}

variable "retention_days" {
  type    = number
  default = 30
}

resource "azurerm_storage_account" "this" {
  name                = var.storage_account_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  account_tier             = "Standard"
  account_replication_type = var.replication_type
  account_kind             = "StorageV2"

  # Policy ZUR-SEC-001 and ZUR-NET-004. None of these are variables on purpose.
  public_network_access_enabled     = false
  allow_nested_items_to_be_public   = false
  shared_access_key_enabled         = false # force Entra ID auth
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  infrastructure_encryption_enabled = true

  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = var.retention_days
    }

    container_delete_retention_policy {
      days = var.retention_days
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_storage_container" "this" {
  for_each              = toset(var.containers)
  name                  = each.value
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}

resource "azurerm_private_endpoint" "blob" {
  name                = "pe-${var.storage_account_name}-blob"
  resource_group_name = var.resource_group_name
  location            = var.location
  subnet_id           = var.private_endpoint_subnet_id
  tags                = var.tags

  private_service_connection {
    name                           = "psc-${var.storage_account_name}-blob"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [var.private_dns_zone_id]
  }
}

output "storage_account_id" { value = azurerm_storage_account.this.id }
output "storage_account_name" { value = azurerm_storage_account.this.name }
output "primary_blob_endpoint" { value = azurerm_storage_account.this.primary_blob_endpoint }
output "container_names" { value = [for c in azurerm_storage_container.this : c.name] }
