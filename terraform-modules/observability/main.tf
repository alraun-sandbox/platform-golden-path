/**
 * Observability baseline.
 *
 * Included in the golden path rather than left to teams because "we could not reconstruct
 * what happened" is the most expensive sentence in an incident review, and because the
 * correlation ID that ties a claim submission across four services is only useful if all four
 * services emit it into the same workspace.
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
variable "log_analytics_name" { type = string }
variable "app_insights_name" { type = string }
variable "tags" { type = map(string) }

variable "retention_days" {
  description = "FINMA expects operational records to be retrievable; 90 days is the floor."
  type        = number
  default     = 90

  validation {
    condition     = var.retention_days >= 30
    error_message = "Log retention below 30 days is not sufficient for incident reconstruction."
  }
}

variable "daily_quota_gb" {
  description = "Cost guard. -1 means unlimited; set a value in non-production."
  type        = number
  default     = 1
}

resource "azurerm_log_analytics_workspace" "this" {
  name                = var.log_analytics_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  sku                        = "PerGB2018"
  retention_in_days          = var.retention_days
  daily_quota_gb             = var.daily_quota_gb
  internet_ingestion_enabled = true
  internet_query_enabled     = true
}

resource "azurerm_application_insights" "this" {
  name                = var.app_insights_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = var.tags

  application_type    = "web"
  workspace_id        = azurerm_log_analytics_workspace.this.id
  retention_in_days   = var.retention_days
  sampling_percentage = 100
}

# A saved query the runbook uses live: follow one claim across every service.
resource "azurerm_log_analytics_saved_search" "claim_trace" {
  name                       = "ClaimCorrelationTrace"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id
  category                   = "RiskGuardian"
  display_name               = "Trace a claim across all services"

  query = <<-KQL
    // Follow a single claim end to end. Replace the correlation id below.
    let correlationId = "REPLACE-ME";
    union AppTraces, AppRequests, AppDependencies, AppExceptions
    | where Properties.CorrelationId == correlationId
        or OperationId == correlationId
    | project TimeGenerated, ItemType, AppRoleName, Message, Name, ResultCode, DurationMs
    | order by TimeGenerated asc
  KQL
}

output "log_analytics_workspace_id" { value = azurerm_log_analytics_workspace.this.id }
output "log_analytics_customer_id" { value = azurerm_log_analytics_workspace.this.workspace_id }
output "app_insights_connection_string" {
  value     = azurerm_application_insights.this.connection_string
  sensitive = true
}
output "app_insights_instrumentation_key" {
  value     = azurerm_application_insights.this.instrumentation_key
  sensitive = true
}
