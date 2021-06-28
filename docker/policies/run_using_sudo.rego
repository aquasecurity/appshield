package appshield.DS010

import data.lib.docker

__rego_metadata__ := {
	"id": "DS010",
	"title": "Run Using Sudo",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Avoid RUN with sudo command as it leads to unpredictable behavior",
	"recommended_actions": "Don't use sudo",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

has_sudo(commands) {
	parts = split(commands, "&&")

	some i
	instruction := parts[i]
	regex.match(`^\s*sudo`, instruction)
}

get_sudo[arg] {
	run = docker.run[_]
	count(run.Value) == 1

	arg := run.Value[0]

	has_sudo(arg)
}

deny[res] {
	args := get_sudo[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
