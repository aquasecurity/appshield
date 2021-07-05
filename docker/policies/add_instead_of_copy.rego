package appshield.dockerfile.DS005

import data.lib.docker

__rego_metadata__ := {
	"id": "DS005",
	"title": "COPY Instead of ADD",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Should use COPY instead of ADD unless, running a tar file",
	"recommended_actions": "Replace ADD by COPY",
	"url": "https://docs.docker.com/engine/reference/builder/#add",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_add[args] {
	add := docker.add[_]
	args := concat(" ", add.Value)

	not contains(args, ".tar")
}

deny[res] {
	args := get_add[_]
	res := sprintf("expected COPY %s instead of ADD %s", [args, args])
}
