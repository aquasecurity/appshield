package appshield.dockerfile.DS009

import data.lib.docker

__rego_metadata__ := {
	"id": "DS009",
	"title": "WORKDIR path not absolute",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "For clarity and reliability, you should always use absolute paths for your WORKDIR.",
	"recommended_actions": "Use absolute paths for your WORKDIR",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_work_dir[arg] {
	workdir := docker.workdir[_]
	arg := workdir.Value[0]

	not regex.match("(^/[A-z0-9-_+]*)|(^[A-z0-9-_+]:\\\\.*)|(^\\$[{}A-z0-9-_+].*)", arg)
}

deny[res] {
	arg := get_work_dir[_]
	res := sprintf("WORKDIR path '%s' should be absolute", [arg])
}
