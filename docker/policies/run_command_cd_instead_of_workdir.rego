package appshield.dockerfile.DS013

import data.lib.docker

__rego_metadata__ := {
	"id": "DS013",
	"title": "RUN Instruction Using 'cd' Instead of WORKDIR",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Use WORKDIR instead of proliferating instructions like RUN cd … && do-something, which are hard to read, troubleshoot, and maintain.",
	"recommended_actions": "Use WORKDIR to change directory",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_cd[args] {
	run := docker.run[_]
	parts = regex.split(`\s*&&\s*`, run.Value[_])
	startswith(parts[_], "cd ")
	args := concat(" ", run.Value)
}

deny[res] {
	args := get_cd[_]
	res := sprintf("RUN shouldn't be used to change directory: '%s'", [args])
}
