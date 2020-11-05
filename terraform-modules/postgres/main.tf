/**
 * PostgreSQL Flexible Server for claims data.
 *
 * Public network access is not a variable. It is not configurable. A team that needs to reach
 * the database from a laptop uses the bastion path, not a firewall rule - because every
 * "temporary" firewall rule in the history of enterprise IT is still there.
 *
 * Note the admin password: it is generated here and written to Key Vault, never rendered into
 * a variable file or a pipeline secret. Policy ZUR-IAM-005 rejects client secrets for exactly
 * this reason, and the same reasoning applies to database credentials.
 */

terraform {
  required_version = ">= 1.9.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "resource_group_name" { type = string }
variable "location" { type = string }
variable "server_name" { type = string }
variable "tags" { type = map(string) }
variable "delegated_subnet_id" { type = string }
variable "private_dns_zone_id" { type = string }
variable "key_vault_id" { type = string }

variable "database_name" {
  type    = string
  default = "riskguardian"
}

variable "administrator_login" {
  type    = string
  default = "rgadmin"
}

variable "postgres_version" {
  type    = string
  default = "16"
}

variable "sku_name" {
  description = "Burstable is adequate for dev; production uses a General Purpose SKU."
  type        = string
  default     = "B_Standard_B1ms"
}

variable "storage_mb" {
  type    = number
  default = 32768
}

variable "backup_retention_days" {
  type    = number
  default = 7

  validation {
    # Swiss financial services retention floor.
    condition     = var.backup_retention_days >= 7
    error_message = "Claims data requires at least 7 days of point-in-time restore."
  }
}

variable "high_availability" {
  type    = bool
  default = false
}

resource "random_password" "administrator" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                = var.server_name
  resource_group_name = var.resource_group_name
  location            = var.location
  version             = var.postgres_version
  tags                = var.tags

  administrator_login    = var.administrator_login
  administrator_password = random_password.administrator.result

  sku_name   = var.sku_name
  storage_mb = var.storage_mb

  backup_retention_days        = var.backup_retention_days
  geo_redundant_backup_enabled = var.high_availability

  # Policy ZUR-SEC-001 and ZUR-NET-004. Deliberately hard-coded.
  public_network_access_enabled = false
  delegated_subnet_id           = var.delegated_subnet_id
  private_dns_zone_id           = var.private_dns_zone_id

  dynamic "high_availability" {
    for_each = var.high_availability ? [1] : []
    content {
      mode = "ZoneRedundant"
    }
  }

  lifecycle {
    ignore_changes = [zone, high_availability[0].standby_availability_zone]
  }
}

resource "azurerm_postgresql_flexible_server_database" "this" {
  name      = var.database_name
  server_id = azurerm_postgresql_flexible_server.this.id
  collation = "en_US.utf8"
  charset   = "utf8"

  lifecycle {
    prevent_destroy = false # dev only; production overrides this to true
  }
}

# Enforce TLS. Azure defaults this on, but an explicit configuration is auditable evidence.
resource "azurerm_postgresql_flexible_server_configuration" "require_secure_transport" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

# Log connections and disconnections - the minimum an auditor asks for.
resource "azurerm_postgresql_flexible_server_configuration" "log_connections" {
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "on"
}

resource "azurerm_key_vault_secret" "connection_string" {
  name         = "riskguardian-db-connection"
  key_vault_id = var.key_vault_id
  content_type = "text/plain"
  tags         = var.tags

  value = format(
    "Host=%s;Port=5432;Database=%s;Username=%s;Password=%s;SslMode=Require;Trust Server Certificate=false",
    azurerm_postgresql_flexible_server.this.fqdn,
    azurerm_postgresql_flexible_server_database.this.name,
    var.administrator_login,
    random_password.administrator.result
  )
}

resource "azurerm_key_vault_secret" "administrator_password" {
  name         = "riskguardian-db-password"
  key_vault_id = var.key_vault_id
  content_type = "text/plain"
  tags         = var.tags
  value        = random_password.administrator.result
}

output "server_id" { value = azurerm_postgresql_flexible_server.this.id }
output "fqdn" { value = azurerm_postgresql_flexible_server.this.fqdn }
output "database_name" { value = azurerm_postgresql_flexible_server_database.this.name }
output "administrator_login" { value = var.administrator_login }
output "password_secret_uri" { value = azurerm_key_vault_secret.administrator_password.versionless_id }
output "connection_string_secret_name" { value = azurerm_key_vault_secret.connection_string.name }
output "connection_string_secret_uri" { value = azurerm_key_vault_secret.connection_string.versionless_id }
