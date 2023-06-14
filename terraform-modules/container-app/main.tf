/**
 * One service, deployed as a Container App.
 *
 * Every service in the estate goes through this module, which is why every service ends up
 * with a user-assigned managed identity, identity-based registry pulls, Key Vault references
 * instead of literal secrets, health probes, and a correlation-ID environment contract -
 * without any team having decided to do those things.
 *
 * The `image` variable is intentionally not defaulted. There is no ":latest" fallback,
 * because the failure mode of a default image tag is a silent deployment of the wrong build.
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
variable "service_name" { type = string }
variable "tags" { type = map(string) }
variable "container_app_environment_id" { type = string }
variable "registry_id" { type = string }
variable "registry_login_server" { type = string }
variable "key_vault_id" { type = string }

variable "image" {
  description = "Fully qualified image reference. Must carry an immutable tag."
  type        = string

  validation {
    condition     = !endswith(var.image, ":latest") && length(regexall(":", var.image)) > 0
    error_message = "Image must carry an explicit, immutable tag - never :latest (Policy ZUR-SUP-006)."
  }
}

variable "target_port" {
  type    = number
  default = 8080
}

variable "external_ingress" {
  description = "Whether this service is reachable from outside the environment."
  type        = bool
  default     = false
}

variable "cpu" {
  type    = number
  default = 0.25
}

variable "memory" {
  type    = string
  default = "0.5Gi"
}

variable "min_replicas" {
  type    = number
  default = 1
}

variable "max_replicas" {
  type    = number
  default = 3
}

variable "env" {
  description = "Plain environment variables. Never put a secret here."
  type        = map(string)
  default     = {}
}

variable "secret_refs" {
  description = "Map of env var name => Key Vault secret versionless URI."
  type        = map(string)
  default     = {}
}

variable "additional_role_assignments" {
  description = "Additional least-privilege grants for the app identity, keyed by purpose."
  type = map(object({
    scope                = string
    role_definition_name = string
  }))
  default = {}
}

variable "health_path" {
  type    = string
  default = "/health/ready"
}

variable "liveness_path" {
  type    = string
  default = "/health/live"
}

resource "azurerm_user_assigned_identity" "this" {
  name                = "id-${var.service_name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

# AcrPull, scoped to the registry. Not Contributor, not on the subscription -
# Policy ZUR-IAM-005 would reject both, including for us.
resource "azurerm_role_assignment" "acr_pull" {
  scope                = var.registry_id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

resource "azurerm_role_assignment" "key_vault_secrets_user" {
  scope                = var.key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

resource "azurerm_role_assignment" "additional" {
  for_each = var.additional_role_assignments

  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = azurerm_user_assigned_identity.this.principal_id
}

locals {
  # Container Apps secret names must be lowercase alphanumeric with dashes.
  secret_name = { for k, v in var.secret_refs : k => lower(replace(k, "_", "-")) }

  base_env = merge(
    {
      ASPNETCORE_ENVIRONMENT           = lookup(var.tags, "Environment", "dev")
      OTEL_SERVICE_NAME                = var.service_name
      RISKGUARDIAN__SERVICE            = var.service_name
      RISKGUARDIAN__CORRELATION_HEADER = "X-Correlation-Id"
    },
    var.env
  )
}

resource "azurerm_container_app" "this" {
  name                         = var.service_name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = var.container_app_environment_id
  revision_mode                = "Single"
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  registry {
    server   = var.registry_login_server
    identity = azurerm_user_assigned_identity.this.id
  }

  dynamic "secret" {
    for_each = var.secret_refs
    content {
      name                = local.secret_name[secret.key]
      key_vault_secret_id = secret.value
      identity            = azurerm_user_assigned_identity.this.id
    }
  }

  ingress {
    external_enabled = var.external_ingress
    target_port      = var.target_port
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = var.service_name
      image  = var.image
      cpu    = var.cpu
      memory = var.memory

      dynamic "env" {
        for_each = local.base_env
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = var.secret_refs
        content {
          name        = env.key
          secret_name = local.secret_name[env.key]
        }
      }

      liveness_probe {
        transport               = "HTTP"
        port                    = var.target_port
        path                    = var.liveness_path
        initial_delay           = 10
        interval_seconds        = 30
        failure_count_threshold = 3
      }

      readiness_probe {
        transport               = "HTTP"
        port                    = var.target_port
        path                    = var.health_path
        interval_seconds        = 10
        failure_count_threshold = 3
      }
    }
  }

  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.key_vault_secrets_user,
    azurerm_role_assignment.additional,
  ]

  lifecycle {
    # The deploy workflow updates the image on every merge; Terraform must not revert it.
    ignore_changes = [template[0].container[0].image]
  }
}

output "fqdn" { value = azurerm_container_app.this.ingress[0].fqdn }
output "url" { value = "https://${azurerm_container_app.this.ingress[0].fqdn}" }
output "identity_principal_id" { value = azurerm_user_assigned_identity.this.principal_id }
output "identity_client_id" { value = azurerm_user_assigned_identity.this.client_id }
output "name" { value = azurerm_container_app.this.name }
