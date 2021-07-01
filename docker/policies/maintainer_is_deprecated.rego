package appshield.DS022

import data.lib.docker

__rego_metadata__ := {
	"id": "DS022",
	"title": "MAINTAINER is deprecated",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "MAINTAINER is deprecated since Docker 1.13.0",
	"recommended_actions": "Remove MAINTAINER command",
	"url": "https://docs.docker.com/engine/deprecated/#maintainer-in-dockerfile",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_maintainer[mntnr] {
	mntnr := input.stages[_][_]
	mntnr.Cmd == "maintainer"
}

deny[res] {
	mntnr := get_maintainer[_]
	res := sprintf("Shouldn't use : %s %s", [mntnr.Cmd, mntnr.Value[0]])
}
