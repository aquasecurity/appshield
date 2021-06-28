package appshield.DS012

__rego_metadata__ := {
	"id": "DS012",
	"title": "Same Alias In Different Froms",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Different FROMS cant have the same alias defined",
	"recommended_actions": "Change aliases to make them different",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_alias[alias] {
	some name
	input.stages[name]

	name_lower = lower(name)
	contains(name_lower, " as ")

	[_, alias] := regex.split(`\s+as\s+`, name_lower)
}

get_aliased_name[arg] {
	some name
	input.stages[name]

	arg = lower(name)
	contains(arg, " as ")
}

fail_same_alias {
	count(get_aliased_name) != count(get_alias)
}

deny[res] {
	fail_same_alias
	res := sprintf("Duplicate alias found among: [%s]", [concat(",", get_aliased_name)])
}
