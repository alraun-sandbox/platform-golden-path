# Policy 1 — No publicly accessible data stores.
#
# Zurich processes policyholder PII and claim documents. A storage account or database that
# accepts traffic from the public internet is a reportable finding under FINMA circular
# 2023/1 operational risk requirements, regardless of whether anything was actually exposed.

package main

import data.lib
import rego.v1

zur_sec_001 := "ZUR-SEC-001"

# --- Storage accounts -------------------------------------------------------

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_account")
	after := lib.after(resource)
	after.allow_nested_items_to_be_public == true
	msg := sprintf(
		"[%s] %s allows public blob access. Set allow_nested_items_to_be_public = false.",
		[zur_sec_001, resource.address],
	)
}

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_account")
	after := lib.after(resource)
	lib.known(after.public_network_access_enabled)
	after.public_network_access_enabled == true
	msg := sprintf(
		"[%s] %s is reachable from the public internet. Set public_network_access_enabled = false and use a private endpoint.",
		[zur_sec_001, resource.address],
	)
}

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_container")
	after := lib.after(resource)
	after.container_access_type != "private"
	msg := sprintf(
		"[%s] %s has container_access_type = %q. Only \"private\" is permitted.",
		[zur_sec_001, resource.address, after.container_access_type],
	)
}

# A default network rule of Allow silently re-opens an account that looks locked down.
deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_account_network_rules")
	after := lib.after(resource)
	after.default_action == "Allow"
	msg := sprintf(
		"[%s] %s sets default_action = \"Allow\". Network rules must default to Deny.",
		[zur_sec_001, resource.address],
	)
}

# --- Databases --------------------------------------------------------------

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_postgresql_flexible_server")
	after := lib.after(resource)
	lib.known(after.public_network_access_enabled)
	after.public_network_access_enabled == true
	msg := sprintf(
		"[%s] %s exposes PostgreSQL to the public internet. Claims data must stay on the private network.",
		[zur_sec_001, resource.address],
	)
}

# 0.0.0.0 as a firewall start address is the Azure idiom for "allow all Azure services",
# and in practice the most common way a database ends up open.
deny contains msg if {
	some resource in lib.changed_of_type("azurerm_postgresql_flexible_server_firewall_rule")
	after := lib.after(resource)
	after.start_ip_address == "0.0.0.0"
	msg := sprintf(
		"[%s] %s opens the database firewall to 0.0.0.0. Use private endpoints instead.",
		[zur_sec_001, resource.address],
	)
}

# --- Key Vault --------------------------------------------------------------

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_key_vault")
	after := lib.after(resource)
	lib.known(after.public_network_access_enabled)
	after.public_network_access_enabled == true
	msg := sprintf(
		"[%s] %s allows public network access to Key Vault.",
		[zur_sec_001, resource.address],
	)
}

# Soft delete plus purge protection is what makes a Key Vault recoverable after an
# accidental or malicious delete. Warn rather than deny - it is not an exposure.
warn contains msg if {
	some resource in lib.changed_of_type("azurerm_key_vault")
	after := lib.after(resource)
	after.purge_protection_enabled != true
	msg := sprintf(
		"[%s] %s has purge protection disabled; secrets are unrecoverable after deletion.",
		[zur_sec_001, resource.address],
	)
}
