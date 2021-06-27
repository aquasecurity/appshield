package appshield.dockerfile.DS004

__rego_metadata__ := {
	"id": "DS004",
	"title": "Exposing Port 22",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Exposing Port 22 allows users to SSH inside the container.",
	"recommended_actions": "Remove port 22 from the dockerfile",
}

# deny_list contains the port numbers which needs to be denied.
deny_list := [22]

# fail_port_check is true if the Dockerfile contains an expose statement for value 22
fail_port_check {
	some i
	input.stages[name][i].Cmd == "EXPOSE"
	val := input.stages[name][i].Value
	val[_] == deny_list[_]
}

deny[res] {
	fail_port_check
	msg := "Specify Port to SSH into the container"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
