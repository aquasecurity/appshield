package appshield.dockerfile.DS004

import data.lib.docker

__rego_metadata__ := {
	"id": "DS004",
	"title": "Port 22 exposed",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Exposing port 22 might allow users to SSH into the container.",
	"recommended_actions": "Remove 'EXPOSE 22' statement from the Dockerfile",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# deny_list contains the port numbers which needs to be denied.
denied_ports := ["22", "22/tcp", "22/udp"]

# fail_port_check is true if the Dockerfile contains an expose statement for value 22
fail_port_check {
	expose := docker.expose[_]
	expose.Value[_] == denied_ports[_]
}

deny[res] {
	fail_port_check
	res := "Port 22 should not be exposed in Dockerfile"
}
