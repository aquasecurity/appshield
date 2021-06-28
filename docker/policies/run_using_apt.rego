package appshield.DS009

import data.lib.docker

__rego_metadata__ := {
	"id": "DS009",
	"title": "Run using APT",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "RUN command is using the 'apt' program.",
	"recommended_actions": "RUN command should not use the 'apt' program",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# run_using_apt is true if the Dockerfile contains run command using apt
run_using_apt {
	run := docker.run[_]
	re_match(`\bapt\b`, run.Value[_])
}

deny[res] {
	run_using_apt
	res := "Remove apt from run command"
}
