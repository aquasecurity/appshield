package appshield.DS012

__rego_metadata__ := {
	"id": "DS012",
	"title": "Same Alias In Different Froms",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Different FROMS can't have the same alias defined",
	"recommended_actions": "Change aliases to make them different",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
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

fail_same_alias {
	count(get_aliased_name) != count(get_alias)
}

deny[res] {
	fail_same_alias
	res := sprintf("Duplicate alias found among: [%s]", [concat(", ", get_aliased_name)])
}
