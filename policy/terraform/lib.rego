# Shared helpers for evaluating a `terraform show -json` plan.
#
# Everything here works on resource_changes so the policies reason about *what will exist
# after apply*, not about HCL text. That matters: an enterprise cannot enforce policy by
# grepping source, because modules, variables and for_each hide the actual values.

package lib

import rego.v1

# Resources being created or updated. Deletions are ignored - you are allowed to delete a
# non-compliant resource.
changed contains resource if {
	some resource in input.resource_changes
	actions := resource.change.actions
	some action in actions
	action in {"create", "update"}
}

# Resources of a given type that are being created or updated.
changed_of_type(t) := {resource |
	some resource in changed
	resource.type == t
}

after(resource) := resource.change.after

# Terraform renders unknown-at-plan-time values as null plus an after_unknown marker.
# Treating unknown as a violation would block every plan that reads an output, so we
# only assert on values we can actually see.
known(value) if {
	value != null
}

address(resource) := resource.address
