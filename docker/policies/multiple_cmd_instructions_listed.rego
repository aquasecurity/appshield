package appshield.DS016

import data.lib.docker

__rego_metadata__ := {
	"id": "DS016",
	"title": "Multiple CMD Instructions Listed",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "There can only be one CMD instruction in a Dockerfile. If you list more than one CMD then only the last CMD will take effect",
	"recommended_actions": "One CMD instruction must remain in Dockerfile. Remove all other instructions",
	"url": "https://docs.docker.com/engine/reference/builder/#cmd",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	cmds := docker.stage_cmd[_]
	cnt := count(cmds)
	cnt > 1
	res := sprintf("There are %d duplicate CMD instructions", [cnt])
}
