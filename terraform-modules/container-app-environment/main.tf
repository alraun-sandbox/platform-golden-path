/**
 * The shared Container Apps environment and its registry.
 *
 * VNet-integrated so that service-to-service traffic stays internal, with the environment
 * itself internet-reachable only through the ingress of apps that explicitly ask for it.
 *
 * The registry is the deliberate, documented exception to "everything private": pulling
 * images from a fully private registry requires either a private build agent or a VNet-joined
 * runner, and neither is worth the complexity for a dev environment. That exception is
 * recorded here in code, with a reason, rather than discovered later in an audit - which is
 * the honest version of policy-as-code.
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
variable "environment_name" { type = string }
variable "registry_name" { type = string }
variable "tags" { type = map(string) }
variable "infrastructure_subnet_id" { type = string }
variable "log_analytics_workspace_id" { type = string }

variable "internal_load_balancer_enabled" {
  description = <<-DESC
    True places the ingress on a private IP. For the dev environment this is false so the
    application is demonstrable; production sets it true and fronts the apps with Front Door.
  DESC
  type        = bool
  default     = false
}

variable "zone_redundancy_enabled" {
  type    = bool
  default = false
}

resource "azurerm_container_registry" "this" {
  name                = var.registry_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  sku           = "Standard"
  admin_enabled = false # identity-based pulls only

  # Immutable tags at the registry level, matching the container policy at build time.
  # Standard SKU does not support this; documented here as the production upgrade path.
  # retention_policy / trust_policy require Premium.
}

resource "azurerm_container_app_environment" "this" {
  name                = var.environment_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  log_analytics_workspace_id     = var.log_analytics_workspace_id
  infrastructure_subnet_id       = var.infrastructure_subnet_id
  internal_load_balancer_enabled = var.internal_load_balancer_enabled
  zone_redundancy_enabled        = var.zone_redundancy_enabled
}

output "environment_id" { value = azurerm_container_app_environment.this.id }
output "environment_default_domain" { value = azurerm_container_app_environment.this.default_domain }
output "registry_id" { value = azurerm_container_registry.this.id }
output "registry_login_server" { value = azurerm_container_registry.this.login_server }
output "registry_name" { value = azurerm_container_registry.this.name }
