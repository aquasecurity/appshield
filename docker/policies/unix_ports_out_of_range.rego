package appshield.DS008

import data.lib.docker

__rego_metadata__ := {
	"id": "DS008",
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

invalid_ports[port] {
	expose := docker.expose[_]
	port := to_number(split(expose.Value[_], "/")[0])
	port > 65535
}

deny[res] {
	port := invalid_ports[_]
	res := sprintf("'EXPOSE' contains port which is out of range [0, 65535]: %d", [port])
}
