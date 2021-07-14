# Policy 3 — Approved regions only.
#
# Swiss insurance data stays in Switzerland, with two EU regions permitted for disaster
# recovery only. This is the policy with the clearest business owner: it is not a security
# preference, it is FINMA outsourcing guidance and GDPR data residency.

package main

import data.lib
import rego.v1

zur_dat_003 := "ZUR-DAT-003"

primary_regions := {"switzerlandnorth", "switzerlandwest"}

dr_regions := {"germanywestcentral", "swedencentral"}

approved_regions := primary_regions | dr_regions

normalise(region) := lower(replace(region, " ", ""))

deny contains msg if {
	some resource in lib.changed
	after := lib.after(resource)
	lib.known(after.location)
	region := normalise(after.location)
	not region in approved_regions
	msg := sprintf(
		"[%s] %s deploys to %q. Swiss policyholder data may only reside in: %v.",
		[zur_dat_003, resource.address, after.location, concat(", ", sort(approved_regions))],
	)
}

# A DR region hosting a production primary is a residency finding waiting to happen.
warn contains msg if {
	some resource in lib.changed
	after := lib.after(resource)
	lib.known(after.location)
	normalise(after.location) in dr_regions
	tags := object.get(after, "tags", {})
	object.get(tags, "Environment", "") == "prod"
	msg := sprintf(
		"[%s] %s places a production resource in the DR region %q. Confirm this is replication, not a primary.",
		[zur_dat_003, resource.address, after.location],
	)
}
