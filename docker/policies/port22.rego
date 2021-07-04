package appshield.dockerfile.DS004

import data.lib.docker

__rego_metadata__ := {
	"id": "DS004",
	"title": "Exposing Port 22",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Exposing Port 22 allows users to SSH inside the container.",
	"recommended_actions": "Remove port 22 from the dockerfile",
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
	res := "Specify Port to SSH into the container"
}
