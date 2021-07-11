package appshield.dockerfile.DS021

import data.lib.docker

__rego_metadata__ := {
	"id": "DS021",
	"title": "'apt-get' missing '-y' to avoid manual input",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "'apt-get' calls should use the flag '-y' to avoid manual user input.",
	"recommended_actions": "Add '-y' flag to 'apt-get'",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	args := get_apt_get[_]
	res := sprintf("'-y' flag is missed: '%s'", [args])
}

get_apt_get[arg] {
	run = docker.run[_]

	count(run.Value) == 1
	arg := run.Value[0]

	is_apt_get(arg)

	not includes_assume_yes(arg)
}

# checking json array
get_apt_get[arg] {
	run = docker.run[_]

	count(run.Value) > 1

	arg := concat(" ", run.Value)

	is_apt_get(arg)

	not includes_assume_yes(arg)
}

is_apt_get(command) {
	regex.match("apt-get (-(-)?[a-zA-Z]+ *)*install(-(-)?[a-zA-Z]+ *)*", command)
}

short_flags := `(-([a-xzA-XZ])*y([a-xzA-XZ])*)`

long_flags := `(--yes)|(--assume-yes)`

optional_not_related_flags := `\s*(-(-)?[a-zA-Z]+\s*)*`

combined_flags := sprintf(`%s(%s|%s)%s`, [optional_not_related_flags, short_flags, long_flags, optional_not_related_flags])

# flags before command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get%sinstall`, [combined_flags])
	regex.match(install_regexp, command)
}

# flags behind command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get%sinstall%s`, [optional_not_related_flags, combined_flags])
	regex.match(install_regexp, command)
}
