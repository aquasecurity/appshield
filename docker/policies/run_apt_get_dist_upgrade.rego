package appshield.dockerfile.DS024

import data.lib.docker

__rego_metadata__ := {
	"id": "DS024",
	"title": "'apt-get dist-upgrade' used",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "'apt-get dist-upgrade' upgrades a major version so it doesn't make more sense in Dockerfile.",
	"recommended_actions": "Just use different image",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_apt_get_dist_upgrade[args] {
	run := docker.run[_]
	regex.match(`apt-get .* dist-upgrade`, run.Value[0])
	args := run.Value[0]
}

deny[res] {
	get_apt_get_dist_upgrade[_]
	res := "'apt-get dist-upgrade' should not be used in Dockerfile"
}
