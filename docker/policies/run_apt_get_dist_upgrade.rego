package appshield.dockerfile.DS024

import data.lib.docker

__rego_metadata__ := {
	"id": "DS024",
	"title": "Do not use apt-get dist-upgrade",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "'dist-upgrade' upgrades a major version so it doesn't make more sense in Dockerfile",
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
	arg := get_apt_get_dist_upgrade[_]
	res := sprintf("%s shouldn't be used in dockerfile", [arg])
}
