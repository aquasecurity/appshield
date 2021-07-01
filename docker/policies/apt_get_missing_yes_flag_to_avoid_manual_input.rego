package appshield.DS021

import data.lib.common
import data.lib.docker

__rego_metadata__ := {
	"id": "DS021",
	"title": "APT-GET Missing '-y' To Avoid Manual Input",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Check if apt-get calls use the flag -y to avoid user manual input.",
	"recommended_actions": "Add -y flag to apt-get",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

short_flags := `(-[^ya..zA..Z]*y[^ya..zA..Z]*)`

long_flags := `(--yes)|(--assume-yes)`

combined_flags := sprintf(`(%s|%s)`, [short_flags, long_flags])

deny[res] {
	args := get_apt_get[_]
	res := sprintf("-y flag is missed: %s", [args])
}

get_apt_get[arg] {
	run = docker.run[_]

	count(run.Value) == 1
	arg := run.Value[0]

	is_apt_get(arg)

	not includes_assume_yes(arg)
}

#checking json array
get_apt_get[arg] {
	run = docker.run[_]

	count(run.Value) > 1

	common.contains_in_array(run.Value, {"apt-get", "install"})

	not flag_includes_assume_yes(run.Value)

	arg := concat(" ", run.Value)
}

is_apt_get(command) {
	regex.match("apt-get (-(-)?[a-z]+ *)*install(-(-)?[a-z]+ *)*", command)
}

flag_includes_assume_yes(parts) {
	regex.match(combined_flags, parts[_])
}

#flags before command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get\s*%s\s*install`, [combined_flags])
	regex.match(install_regexp, command)
}

#flags after command
includes_assume_yes(command) {
	install_regexp := sprintf(`apt-get\s+install\s+%s`, [combined_flags])
	regex.match(install_regexp, command)
}
