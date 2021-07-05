package appshield.dockerfile.DS018

import data.lib.docker

__rego_metadata__ := {
	"id": "DS018",
	"title": "COPY '--from' Without FROM Alias Defined Previously",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "COPY command with the flag '--from' should mention a previously defined FROM alias",
	"recommended_actions": "Fix alias",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_copy_arg[arg] {
	copy := docker.copy[_]

	arg := copy.Flags[x]
	contains(arg, "--from=")
	arg != "--from=0"
	aux_split := split(arg, "=")

	not alias_exists(aux_split[1])
}

deny[res] {
	arg := get_copy_arg[_]
	res := sprintf("Invalid alias: %s", [arg])
}

alias_exists(from_alias) {
	alias := get_alias[_]
	from_alias == alias
}

get_alias[alias] {
	name := get_aliased_name[_]
	[_, alias] := regex.split(`\s+as\s+`, name)
}

get_aliased_name[arg] {
	some name
	input.stages[name]

	arg = lower(name)
	contains(arg, " as ")
}
