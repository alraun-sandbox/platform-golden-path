# Container image policy.
#
# Scenario 6 in the flaw catalogue is a Dockerfile pinned to `:latest`. It looks harmless and
# it is the reason "it worked in test" stops being a meaningful statement: the artifact that
# passed the gate is not the artifact that shipped.

package main

import rego.v1

zur_sup_006 := "ZUR-SUP-006"

instructions(cmd) := [instruction |
	some instruction in input
	lower(instruction.Cmd) == cmd
]

base_images contains image if {
	some instruction in instructions("from")
	image := instruction.Value[0]
}

deny contains msg if {
	some image in base_images
	endswith(lower(image), ":latest")
	msg := sprintf(
		"[%s] Base image %q uses the :latest tag. Pin an immutable tag or a digest - a build must be reproducible.",
		[zur_sup_006, image],
	)
}

deny contains msg if {
	some image in base_images
	not contains(image, ":")
	not contains(image, "$")
	msg := sprintf(
		"[%s] Base image %q has no tag, which resolves to :latest.",
		[zur_sup_006, image],
	)
}

warn contains msg if {
	some image in base_images
	not contains(image, "@sha256:")
	contains(image, ":")
	not endswith(lower(image), ":latest")
	msg := sprintf(
		"[%s] Base image %q is tag-pinned but not digest-pinned. Tags are mutable.",
		[zur_sup_006, image],
	)
}

# Containers must not run as root. Azure Container Apps will happily run a root container.
deny contains msg if {
	count(instructions("user")) == 0
	msg := sprintf(
		"[%s] No USER instruction; the container runs as root.",
		[zur_sup_006],
	)
}

deny contains msg if {
	some instruction in instructions("user")
	user := lower(instruction.Value[0])
	user in {"root", "0"}
	msg := sprintf(
		"[%s] USER is set to %q.",
		[zur_sup_006, instruction.Value[0]],
	)
}

# A healthcheck is what lets the deployment workflow verify a revision instead of assuming it.
warn contains msg if {
	count(instructions("healthcheck")) == 0
	msg := sprintf(
		"[%s] No HEALTHCHECK instruction; rollout health cannot be verified from the image.",
		[zur_sup_006],
	)
}

# Build arguments are visible in image history - they are not a secret mechanism.
deny contains msg if {
	some instruction in instructions("arg")
	arg := lower(instruction.Value[0])
	some marker in {"password", "secret", "token", "apikey", "api_key"}
	contains(arg, marker)
	msg := sprintf(
		"[%s] ARG %q looks like a credential. Build arguments persist in image history; use a runtime secret.",
		[zur_sup_006, instruction.Value[0]],
	)
}
