package appshield.dockerfile.DS017

import data.lib.docker

__rego_metadata__ := {
	"id": "DS017",
	"title": "'RUN <package-manager> update' instruction alone",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement.",
	"recommended_actions": "Combine '<package-manager> update' and '<package-manager> install' instructions to single one",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	run := docker.run[_]

	command = concat(" ", run.Value)

	is_valid_update(command)
	not update_followed_by_install(command)

	res := __rego_metadata__.description
}

is_valid_update(command) {
	chained_parts := regex.split(`\s*&&\s*`, command)

	array_split := split(chained_parts[_], " ")

	len = count(array_split)

	update := {"update", "--update"}

	array_split[minus(len, 1)] == update[_]
}

update_followed_by_install(command) {
	command_list = [
		"install",
		"source-install",
		"reinstall",
		"groupinstall",
		"localinstall",
		"apk add",
	]

	update := indexof(command, "update")
	update != -1

	install := indexof(command, command_list[_])
	install != -1

	update < install
}
