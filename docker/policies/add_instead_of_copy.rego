package appshield.dockerfile.DS005

import data.lib.docker

__rego_metadata__ := {
	"id": "DS005",
	"title": "ADD is used instead of COPY",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "You should use COPY instead of ADD unless you want to extract a tar file. Note that ADD command will extract a tar file, which adds the risk of Zip based vulnerabilities. Due to that it is adviced to use COPY command, which does not extract tar files.",
	"recommended_actions": "Use COPY instead of ADD",
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
	res := sprintf("Consider using 'COPY %s' command instead of 'ADD %s'", [args, args])
}
