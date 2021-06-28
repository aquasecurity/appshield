package appshield.DS009

__rego_metadata__ := {
	"id": "DS009",
	"title": "WORKDIR Path Not Absolute",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "For clarity and reliability, you should always use absolute paths for your WORKDIR",
	"recommended_actions": "Use absolute paths for your WORKDIR",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#workdir",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_work_dir[arg] {
	some i
	cmd_obj := input.stages[name][i]
	cmd_obj.Cmd == "workdir"
	arg := cmd_obj.Value[0]

	not regex.match("(^/[A-z0-9-_+]*)|(^[A-z0-9-_+]:\\\\.*)|(^\\$[{}A-z0-9-_+].*)", arg)
}

fail_work_dir {
	count(get_work_dir) > 0
}

deny[res] {
	fail_work_dir
	arg := get_work_dir[_]
	res := sprintf("Path %s isn't absolute", [arg])
}
