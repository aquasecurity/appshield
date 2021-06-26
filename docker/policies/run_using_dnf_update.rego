package appshield.DS012

__rego_metadata__ := {
	"id": "DS012",
	"title": "Run Using dnf Update",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Command 'dnf update' should not be used, as it can cause inconsistencies between builds and fails in updated packages",
	"recommended_actions": "Remove 'dnf update'",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_update[args] {
	commands = [
		"dnf update",
		"dnf upgrade",
		"dnf upgrade-minimal",
	]

	some i

	cmd_obj := input.stages[name][i]

	cmd_obj.Cmd == "run"

	args := concat(" ", cmd_obj.Value)

	contains(args, commands[_])
}

fail_update {
	count(get_update) > 0
}

deny[res] {
	fail_update
	args := get_update[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
