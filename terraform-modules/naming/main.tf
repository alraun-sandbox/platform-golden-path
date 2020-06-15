/**
 * Naming and tagging convention.
 *
 * Every other module takes its names and tags from here. That is what makes Policy 2
 * (mandatory tags) and the CH-<BU>-<4 digits> cost-centre format pass without any team having
 * to know the rule: the golden path produces compliant resources by construction, and the
 * policy gate is only there to catch the cases that left the path.
 *
 * "Make the compliant thing the easy thing" is the single highest-leverage move in enterprise
 * DevSecOps, and it is almost never a security control - it is a module like this one.
 */

variable "workload" {
  description = "Workload short name, e.g. riskguardian."
  type        = string
  default     = "riskguardian"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,15}$", var.workload))
    error_message = "workload must be 3-16 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "dev | test | prod"
  type        = string

  validation {
    condition     = contains(["dev", "test", "prod"], var.environment)
    error_message = "environment must be one of dev, test, prod (Policy ZUR-GOV-002)."
  }
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "switzerlandnorth"

  validation {
    # Enforced again at plan time by Policy ZUR-DAT-003. Failing here is faster and kinder:
    # the developer finds out in `terraform validate`, not in code review.
    condition = contains(
      ["switzerlandnorth", "switzerlandwest", "germanywestcentral", "swedencentral"],
      var.location
    )
    error_message = "Swiss policyholder data may only reside in an approved region (Policy ZUR-DAT-003)."
  }
}

variable "owner" {
  description = "Owning team. Must be a reachable group, not a person."
  type        = string

  validation {
    condition     = length(trimspace(var.owner)) >= 3
    error_message = "owner must identify a real team (Policy ZUR-GOV-002)."
  }
}

variable "cost_center" {
  description = "Cost centre in the form CH-<BU>-<4 digits>."
  type        = string

  validation {
    condition     = can(regex("^CH-[A-Z]+-[0-9]{4}$", var.cost_center))
    error_message = "cost_center must match CH-<BU>-<4 digits> (Policy ZUR-GOV-002)."
  }
}

variable "data_classification" {
  description = "public | internal | confidential | restricted"
  type        = string
  default     = "confidential"

  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "data_classification must be public, internal, confidential or restricted."
  }
}

variable "extra_tags" {
  description = "Additional tags merged on top of the mandatory set."
  type        = map(string)
  default     = {}
}

locals {
  # Region short codes keep names inside Azure's length limits.
  location_short = {
    switzerlandnorth   = "chn"
    switzerlandwest    = "chw"
    germanywestcentral = "gwc"
    swedencentral      = "sec"
  }[var.location]

  suffix         = "${var.workload}-${var.environment}-${local.location_short}"
  suffix_compact = replace(local.suffix, "-", "")

  tags = merge(
    {
      Environment        = var.environment
      Owner              = var.owner
      CostCenter         = var.cost_center
      DataClassification = var.data_classification
      Workload           = var.workload
      ManagedBy          = "terraform"
      GoldenPath         = "platform-golden-path"
    },
    var.extra_tags
  )
}

output "tags" {
  description = "The mandatory tag set. Apply to every taggable resource."
  value       = local.tags
}

output "suffix" {
  description = "Hyphenated naming suffix, e.g. riskguardian-dev-chn."
  value       = local.suffix
}

output "resource_group_name" {
  value = "rg-${local.suffix}"
}

output "key_vault_name" {
  # Key Vault names are limited to 24 characters and forbid hyphens at the edges.
  value = substr("kv${local.suffix_compact}", 0, 24)
}

output "storage_account_name" {
  # Storage accounts: 3-24 characters, lowercase alphanumeric only.
  value = substr("st${local.suffix_compact}", 0, 24)
}

output "container_registry_name" {
  value = substr("acr${local.suffix_compact}", 0, 50)
}

output "postgres_server_name" {
  value = "psql-${local.suffix}"
}

output "container_app_environment_name" {
  value = "cae-${local.suffix}"
}

output "log_analytics_name" {
  value = "log-${local.suffix}"
}

output "app_insights_name" {
  value = "appi-${local.suffix}"
}

output "vnet_name" {
  value = "vnet-${local.suffix}"
}

output "location" {
  value = var.location
}
