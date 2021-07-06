package appshield.dockerfile.DS020

import data.lib.docker

__rego_metadata__ := {
	"id": "DS020",
	"title": "Missing 'zypper clean' after running zypper",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Reduce layer and image size by deleting unneeded caches after running zypper",
	"recommended_actions": "Add 'zypper clean' to Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

install_regex := `(zypper in)|(zypper remove)|(zypper rm)|(zypper source-install)|(zypper si)|(zypper patch)|(zypper (-(-)?[a-zA-Z]+ *)*install)`

zypper_regex = sprintf("%s|(zypper clean)|(zypper cc)", [install_regex])

get_zypper[arg] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match(install_regex, arg)

	not contains_zipper_clean(arg)
}

deny[res] {
	args := get_zypper[_]
	res := sprintf("'zypper clean' is missed: '%s'", [args])
}

contains_zipper_clean(cmd) {
	zypper_commands := regex.find_n(zypper_regex, cmd, -1)

	is_zypper_clean(zypper_commands[minus(count(zypper_commands), 1)])
}

is_zypper_clean(cmd) {
	cmd == "zypper clean"
}

is_zypper_clean(cmd) {
	cmd == "zypper cc"
}
