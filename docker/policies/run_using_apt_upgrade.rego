package appshield.DS006

__rego_metadata__ := {
	"id": "DS006",
	"title": "Run Using Upgrade Commands",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Commands 'apt-get upgrade' and 'apt-get dist-upgrade' should not be used",
	"recommended_actions": "You should not even use 'apt-get upgrade' and 'apt-get dist-upgrade'.",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_upgrade[args] {
	some i
	input.stages[name][i].Cmd == "run"

	merged := concat(" ", input.stages[name][i].Value)

	regex.match("(apt-get upgrade)|(apt-get dist-upgrade)", merged)

	args := merged
}

fail_upgrade {
	count(get_upgrade) > 0
}

deny[res] {
	fail_upgrade
	args := get_upgrade[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
