package appshield.DS013

__rego_metadata__ := {
	"id": "DS013",
	"title": "Use of Apk Upgrade",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Avoid usage of apk upgrade because some packages from the parent image cannot be upgraded inside an unprivileged container",
	"recommended_actions": "Don't use apk upgrade",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_upgrade[arg] {
	some i
	cmd_obj := input.stages[name][i]
	cmd_obj.Cmd == "run"

	arg := cmd_obj.Value[0]

	regex.match(".*apk.*upgrade", arg)
}

fail_upgrade {
	count(get_upgrade) > 0
}

deny[res] {
	fail_upgrade
	args := get_upgrade[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
