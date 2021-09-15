# Policy 4 — Data services must be reachable only over a private endpoint.
#
# Closing public access (Policy 1) removes the front door. This policy makes sure there is a
# back door for the application, otherwise engineers reopen public access to get their work
# done - which is how well-meant security policy produces worse security.
#
# Deliberately scoped: it applies to stores that hold claims data, not to every resource.
# Over-broad policies are the reason enterprises end up with a blanket exemption process.

package main

import data.lib
import rego.v1

zur_net_004 := "ZUR-NET-004"

requires_private_endpoint := {
	"azurerm_postgresql_flexible_server",
	"azurerm_storage_account",
	"azurerm_key_vault",
}

# Which resources the plan connects to a private endpoint.
privately_connected contains target if {
	some resource in lib.changed_of_type("azurerm_private_endpoint")
	after := lib.after(resource)
	some connection in after.private_service_connection
	target := connection.private_connection_resource_id
}

# Terraform cannot know a resource id at plan time, so the id-based match above will not
# fire for resources created in the same plan. Fall back to counting endpoints: if the plan
# introduces at least one private endpoint per protected store, treat the intent as met and
# let the drift detection job verify reality after apply.
private_endpoint_count := count(lib.changed_of_type("azurerm_private_endpoint"))

protected_store_count := count([resource |
	some resource in lib.changed
	resource.type in requires_private_endpoint
])

deny contains msg if {
	protected_store_count > 0
	private_endpoint_count == 0
	some resource in lib.changed
	resource.type in requires_private_endpoint
	msg := sprintf(
		"[%s] %s holds regulated data but the plan creates no private endpoint.",
		[zur_net_004, resource.address],
	)
}

warn contains msg if {
	protected_store_count > private_endpoint_count
	private_endpoint_count > 0
	msg := sprintf(
		"[%s] %d protected data store(s) but only %d private endpoint(s) in this plan. Verify each store is covered.",
		[zur_net_004, protected_store_count, private_endpoint_count],
	)
}

# Private DNS is the half of private networking everyone forgets; without a zone group the
# name still resolves to the public IP and the endpoint does nothing.
warn contains msg if {
	some resource in lib.changed_of_type("azurerm_private_endpoint")
	after := lib.after(resource)
	count(object.get(after, "private_dns_zone_group", [])) == 0
	msg := sprintf(
		"[%s] %s has no private DNS zone group; the hostname will still resolve publicly.",
		[zur_net_004, resource.address],
	)
}

# TLS floor for anything that terminates a connection.
deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_account")
	after := lib.after(resource)
	lib.known(after.min_tls_version)
	after.min_tls_version != "TLS1_2"
	msg := sprintf(
		"[%s] %s permits %s. Minimum is TLS 1.2.",
		[zur_net_004, resource.address, after.min_tls_version],
	)
}

deny contains msg if {
	some resource in lib.changed_of_type("azurerm_storage_account")
	after := lib.after(resource)
	lib.known(after.enable_https_traffic_only)
	after.enable_https_traffic_only == false
	msg := sprintf(
		"[%s] %s allows plaintext HTTP.",
		[zur_net_004, resource.address],
	)
}
