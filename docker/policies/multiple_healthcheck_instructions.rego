package appshield.dockerfile.DS023

import data.lib.docker

__rego_metadata__ := {
	"id": "DS023",
	"title": "Multiple HEALTHCHECK defined",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Providing more than one HEALTHCHECK instruction per stage is confusing and error-prone.",
	"recommended_actions": "One HEALTHCHECK instruction must remain in Dockerfile. Remove all other instructions.",
	"url": "https://docs.docker.com/engine/reference/builder/#healthcheck",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	healthchecks := docker.stage_healthcheck[name]
	cnt := count(healthchecks)
	cnt > 1
	res := sprintf("There are %d duplicate HEALTHCHECK instructions in the stage '%s'", [cnt, name])
}
