package appshield.DS014

__rego_metadata__ := {
	"id": "DS014",
	"title": "Run Using Sudo",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Avoid RUN with sudo command as it leads to unpredictable behavior",
	"recommended_actions": "Don't use sudo",
	"url": "https://docs.docker.com/engine/reference/builder/#run",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

has_sudo(commands) {
	parts = split(commands, "&&")

	some i
	instruction := parts[i]
	regex.match("^( )*sudo", instruction)
}

get_sudo[arg] {
	some i
	cmd_obj := input.stages[name][i]
	cmd_obj.Cmd == "run"
	count(cmd_obj.Value) == 1

	arg := cmd_obj.Value[0]

	has_sudo(arg)
}

fail_sudo {
	count(get_sudo) > 0
}

deny[res] {
	fail_sudo
	args := get_sudo[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
