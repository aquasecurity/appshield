package appshield.DS017

import data.lib.docker

__rego_metadata__ := {
	"id": "DS017",
	"title": "Update Instruction Alone",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement",
	"recommended_actions": "Combine instructions to single one",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	run := docker.run[_]
	count(run.Value) == 1
	command := run.Value[0]

	is_valid_update(command)
	not update_followed_by_install(command)

	res := sprintf("%s should be followed by install", [concat(" ", run.Value)])
}

is_valid_update(command) {
	contains(command, " update ")
}

is_valid_update(command) {
	contains(command, " --update ")
}

is_valid_update(command) {
	array_split := split(command, " ")

	len = count(array_split)

	update := {"update", "--update"}

	array_split[minus(len, 1)] == update[j]
}

update_followed_by_install(command) {
	command_list = [
		"install",
		"source-install",
		"reinstall",
		"groupinstall",
		"localinstall",
		"add",
	]

	update := indexof(command, "update")
	update != -1

	install := indexof(command, command_list[_])
	install != -1

	update < install
}
