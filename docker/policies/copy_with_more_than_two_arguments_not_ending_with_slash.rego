package appshield.DS015

__rego_metadata__ := {
	"id": "DS015",
	"title": "Copy With More Than Two Arguments Not Ending With Slash",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "When a COPY command has more than two arguments, the last one should end with a slash",
	"recommended_actions": "Add slash to last COPY argument",
	"url": "https://docs.docker.com/engine/reference/builder/#copy",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_copy_arg[arg] {
	some i
	cmd_obj := input.stages[name][i]
	cmd_obj.Cmd == "copy"

	cnt := count(cmd_obj.Value)

	cnt > 2

	arg := cmd_obj.Value[minus(cnt, 1)]

	not endswith(arg, "/")
}

fail_copy {
	count(get_copy_arg) > 0
}

deny[res] {
	fail_copy
	arg := get_copy_arg[_]
	res := sprintf("Slash is expected at the end of %s", [arg])
}
