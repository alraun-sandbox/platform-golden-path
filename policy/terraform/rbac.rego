# Policy 5 — Least privilege in RBAC.
#
# Owner and Contributor-at-subscription-scope are how a compromised pipeline becomes a
# compromised tenant. This policy is also the reason our own provisioning script grants the
# deployment identity Contributor on a single resource group: a platform team that exempts
# itself from its own policy has no policy.

package main

import data.lib
import rego.v1

zur_iam_005 := "ZUR-IAM-005"

forbidden_roles := {"Owner", "User Access Administrator"}

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_role_assignment")
	after := lib.after(resource)
	lib.known(after.role_definition_name)
	after.role_definition_name in forbidden_roles
	msg := sprintf(
		"[%s] %s grants %q. Use a scoped built-in role or a custom role instead.",
		[zur_iam_005, resource.address, after.role_definition_name],
	)
}

# Scope matters more than role name: Contributor on a subscription is worse than Owner on
# one resource group.
deny contains msg if {
	some resource in lib.changed_of_type("azurerm_role_assignment")
	after := lib.after(resource)
	lib.known(after.scope)
	regex.match(`^/subscriptions/[^/]+$`, after.scope)
	msg := sprintf(
		"[%s] %s is scoped to an entire subscription. Scope role assignments to a resource group or resource.",
		[zur_iam_005, resource.address],
	)
}

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_role_assignment")
	after := lib.after(resource)
	lib.known(after.scope)
	startswith(after.scope, "/providers/Microsoft.Management/managementGroups/")
	msg := sprintf(
		"[%s] %s is scoped to a management group.",
		[zur_iam_005, resource.address],
	)
}

# Wide data-plane grants on the vault holding claims encryption keys.
warn contains msg if {
	some resource in lib.changed_of_type("azurerm_key_vault_access_policy")
	after := lib.after(resource)
	some permission in object.get(after, "secret_permissions", [])
	permission == "Purge"
	msg := sprintf(
		"[%s] %s grants Purge on Key Vault secrets.",
		[zur_iam_005, resource.address],
	)
}

# Managed identity is the whole point of the OIDC story. A service principal password in a
# plan means a secret is about to exist somewhere.
deny contains msg if {
	some resource in lib.changed_of_type("azuread_application_password")
	msg := sprintf(
		"[%s] %s creates a client secret. This estate authenticates with workload identity federation only.",
		[zur_iam_005, resource.address],
	)
}
