package appshield.DS010

__rego_metadata__ := {
	"id": "DS010",
	"title": "UNIX Ports Out Of Range",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Exposing UNIX ports out of range from 0 to 65535",
	"recommended_actions": "Use port number within range",
	"url": "https://docs.docker.com/engine/reference/builder/#expose",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

getPorts[args] {
	some i, name
	input.stages[name][i].Cmd == "expose"
	cmd := input.stages[name][i]

	port := to_number(split(cmd.Value[_], "/")[0])
	port > 65535
	args := port
}

failExposePorts {
	count(getPorts) > 0
}

deny[res] {
	failExposePorts
	port := getPorts[_]
	res := sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [port])
}
