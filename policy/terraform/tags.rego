# Policy 2 — Mandatory tags.
#
# Unglamorous and the single most useful policy in a large enterprise: without Owner and
# CostCenter nobody can answer "who pays for this and who do I call at 03:00", and the
# resource is never decommissioned. Tag drift is how cloud bills grow.

package main

import data.lib
import rego.v1

zur_gov_002 := "ZUR-GOV-002"

required_tags := {"Environment", "Owner", "CostCenter"}

allowed_environments := {"dev", "test", "prod"}

# Tags are inherited from the resource group by convention, not by Azure. These types
# genuinely carry their own tags and are the ones auditors ask about.
taggable := {
	"azurerm_resource_group",
	"azurerm_storage_account",
	"azurerm_key_vault",
	"azurerm_postgresql_flexible_server",
	"azurerm_container_app",
	"azurerm_container_app_environment",
	"azurerm_container_registry",
	"azurerm_log_analytics_workspace",
	"azurerm_application_insights",
	"azurerm_virtual_network",
	"azurerm_subnet_network_security_group_association",
	"azurerm_network_security_group",
}

deny contains msg if {
	some resource in lib.changed
	resource.type in taggable
	after := lib.after(resource)
	tags := object.get(after, "tags", {})
	missing := required_tags - {key | some key, _ in tags}
	count(missing) > 0
	msg := sprintf(
		"[%s] %s is missing required tag(s): %v.",
		[zur_gov_002, resource.address, concat(", ", sort(missing))],
	)
}

deny contains msg if {
	some resource in lib.changed
	resource.type in taggable
	after := lib.after(resource)
	tags := object.get(after, "tags", {})
	value := tags.Environment
	not value in allowed_environments
	msg := sprintf(
		"[%s] %s has Environment = %q. Allowed: %v.",
		[zur_gov_002, resource.address, value, concat(", ", sort(allowed_environments))],
	)
}

# An owner has to be reachable. "team", "tbd" or an empty string is not an owner.
placeholder_owners := {"tbd", "todo", "tba", "n/a", "na", "none", "unknown", "team", "test", "-"}

deny contains msg if {
	some resource in lib.changed
	resource.type in taggable
	after := lib.after(resource)
	tags := object.get(after, "tags", {})
	owner := tags.Owner
	is_placeholder_owner(owner)
	msg := sprintf(
		"[%s] %s has an Owner tag that identifies nobody (%q). Name a team that can be paged.",
		[zur_gov_002, resource.address, owner],
	)
}

is_placeholder_owner(owner) if {
	count(trim_space(owner)) < 4
}

is_placeholder_owner(owner) if {
	lower(trim_space(owner)) in placeholder_owners
}

# Cost centres at Zurich are CH-<BU>-<4 digits>.
deny contains msg if {
	some resource in lib.changed
	resource.type in taggable
	after := lib.after(resource)
	tags := object.get(after, "tags", {})
	cc := tags.CostCenter
	not regex.match(`^CH-[A-Z]+-[0-9]{4}$`, cc)
	msg := sprintf(
		"[%s] %s has CostCenter = %q, which does not match CH-<BU>-<4 digits>.",
		[zur_gov_002, resource.address, cc],
	)
}

warn contains msg if {
	some resource in lib.changed
	resource.type in taggable
	after := lib.after(resource)
	tags := object.get(after, "tags", {})
	not "DataClassification" in {key | some key, _ in tags}
	msg := sprintf(
		"[%s] %s has no DataClassification tag; default handling rules will apply.",
		[zur_gov_002, resource.address],
	)
}
