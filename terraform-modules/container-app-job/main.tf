/**
 * A one-shot Container Apps job.
 *
 * The estate needs this for database migration and seeding, and the reason is worth
 * stating plainly: our PostgreSQL Flexible Server sits on a delegated subnet behind a
 * private DNS zone, so nothing outside the VNet can reach it. There is no
 * /docker-entrypoint-initdb.d hook on a managed server, and no way to run psql from a
 * laptop or a hosted runner without punching a hole in exactly the network controls the
 * rest of this repository exists to enforce.
 *
 * So the seeding runs from inside, as a job on the same Container Apps environment. The
 * compliant path costs more machinery than the non-compliant one - and that is the honest
 * version of the policy-as-code story, not a footnote to hide.
 *
 * Jobs inherit the same platform defaults as services: a user-assigned identity,
 * identity-based registry pulls, Key Vault references rather than literal secrets, and no
 * ":latest" tag. A short-lived job is not exempt from the controls just because it exits.
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
variable "job_name" { type = string }
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

variable "cpu" {
  type    = number
  default = 0.5
}

variable "memory" {
  type    = string
  default = "1Gi"
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
  description = "Additional least-privilege grants for the job identity, keyed by purpose."
  type = map(object({
    scope                = string
    role_definition_name = string
  }))
  default = {}
}

variable "replica_timeout_in_seconds" {
  description = "How long one attempt may run before the platform kills it."
  type        = number
  default     = 1800
}

variable "replica_retry_limit" {
  description = <<-EOT
    Retries per execution. Defaults to 1 rather than 0 because the platform can lose a
    replica to a transient node or network fault, and a private DNS record may not have
    propagated on the very first attempt.

    This is only safe because the workloads we run here are idempotent. A retried seeding
    job that re-inserted its rows would double the data silently - no error, just wrong
    numbers - so the runner keeps a ledger of what it has already applied.
  EOT
  type        = number
  default     = 1
}

resource "azurerm_user_assigned_identity" "this" {
  name                = "id-${var.job_name}"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags
}

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
  secret_name = { for k, v in var.secret_refs : k => lower(replace(k, "_", "-")) }

  base_env = merge(
    {
      RISKGUARDIAN__SERVICE = var.job_name
    },
    var.env
  )
}

resource "azurerm_container_app_job" "this" {
  name                         = var.job_name
  resource_group_name          = var.resource_group_name
  location                     = var.location
  container_app_environment_id = var.container_app_environment_id
  tags                         = var.tags

  replica_timeout_in_seconds = var.replica_timeout_in_seconds
  replica_retry_limit        = var.replica_retry_limit

  # Manual, not scheduled. Seeding is something a human decides to do after an apply,
  # and a cron that silently re-runs against a live database is a bad idea even when
  # the job is idempotent.
  manual_trigger_config {
    parallelism              = 1
    replica_completion_count = 1
  }

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

  template {
    container {
      name   = var.job_name
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
    }
  }

  depends_on = [
    azurerm_role_assignment.acr_pull,
    azurerm_role_assignment.key_vault_secrets_user,
    azurerm_role_assignment.additional,
  ]

  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }
}

output "name" { value = azurerm_container_app_job.this.name }
output "identity_principal_id" { value = azurerm_user_assigned_identity.this.principal_id }
output "identity_client_id" { value = azurerm_user_assigned_identity.this.client_id }
