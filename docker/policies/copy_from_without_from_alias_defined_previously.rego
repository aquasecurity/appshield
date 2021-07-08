package appshield.dockerfile.DS018

import data.lib.docker

__rego_metadata__ := {
	"id": "DS018",
	"title": "'COPY --from' refers to alias not defined previously",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "COPY command with the flag '--from' should mention a previously defined FROM alias.",
	"recommended_actions": "Specify an alias defined previously",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_copy_arg[arg] {
	copy := docker.copy[_]

	arg := copy.Flags[_]

	contains(arg, "--from=")
	not regex.match("--from=\\d+", arg)

	aux_split := split(arg, "=")

	not alias_exists(aux_split[1], copy.Stage)
}

deny[res] {
	arg := get_copy_arg[_]
	res := sprintf("The alias '%s' is not defined in the previous stages", [arg])
}

alias_exists(from_alias, max_stage_idx) {
	alias := get_alias(max_stage_idx)[_]
	from_alias == alias
}

get_alias(max_stage_idx) = res {
	res := {alias |
		name := get_aliased_name(max_stage_idx)[_]
		[_, alias] := regex.split(`\s+as\s+`, name)
	}
}

get_aliased_name(max_stage_idx) = res {
	res := {n |
		c := input.stages[name][_]
		c.Stage <= max_stage_idx # there is another rule that covers self reference
		name_lower = lower(name)
		contains(name_lower, " as ")
		n := name_lower
	}
}
