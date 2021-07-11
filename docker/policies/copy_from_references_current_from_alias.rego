package appshield.dockerfile.DS006

import data.lib.docker

__rego_metadata__ := {
	"id": "DS006",
	"title": "COPY '--from' referring to the current image",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself.",
	"recommended_actions": "Change the '--form' so that it will not refer to itself",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_alias_from_copy[args] {
	copies := docker.stage_copies[stage]

	flag := copies[_].Flags[_]
	contains(flag, "--from=")
	parts := split(flag, "=")

	is_alias_current_from_alias(stage, parts[1])
	args := parts[1]
}

is_alias_current_from_alias(current_name, current_alias) = allow {
	current_name_lower := lower(current_name)
	current_alias_lower := lower(current_alias)

	#expecting stage name as "myimage:tag as dep"
	[_, alias] := regex.split(`\s+as\s+`, current_name_lower)

	alias == current_alias

	allow = true
}

deny[res] {
	args := get_alias_from_copy[_]
	res := sprintf("'COPY --from' should not mention current alias '%s' since it is impossible to copy from itself", [args])
}
