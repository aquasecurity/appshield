package appshield.DS007

import data.lib.docker

__rego_metadata__ := {
	"id": "DS007",
	"title": "Multiple ENTRYPOINT Instructions Listed",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect",
	"recommended_actions": "Remove unnecessary ENTRYPOINT instruction.",
	"url": "https://docs.docker.com/engine/reference/builder/#entrypoint",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	entrypoints := docker.stage_entrypoints[_]
	count(entrypoints) > 1
	res := sprintf("There are %d duplicate ENTRYPOINT instructions", [count(entrypoints)])
}
