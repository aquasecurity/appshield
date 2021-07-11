package appshield.dockerfile.DS010

import data.lib.docker

__rego_metadata__ := {
	"id": "DS010",
	"title": "RUN using 'sudo'",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Avoid using 'RUN' with 'sudo' commands, as it can lead to unpredictable behavior.",
	"recommended_actions": "Don't use sudo",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

has_sudo(commands) {
	parts = split(commands, "&&")

	instruction := parts[_]
	regex.match(`^\s*sudo`, instruction)
}

get_sudo[arg] {
	run = docker.run[_]
	count(run.Value) == 1

	arg := run.Value[0]

	has_sudo(arg)
}

deny[res] {
	count(get_sudo) > 0
	res := "Using 'sudo' in Dockerfile should be avoided"
}
