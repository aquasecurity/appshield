package appshield.dockerfile.DS004

__rego_metadata__ := {
	"id": "DS004",
	"title": "Exposing Port 22",
	"version": "v1.0.0",
	"severity": "Medium",
	"type": "Dockerfile Security Check",
	"description": "Exposing Port 22 allows users to SSH inside the container.",
	"recommended_actions": "Remove port 22 from the dockerfile",
}

#denyList contains the port numbers which needs to be denied.
denyList := [22]

# failPortCheck is true if the Dockerfile contains an expose statement for value 22
fail {
	failPortCheck
}

failPortCheck {
	some i
	input[i].Cmd == "EXPOSE"
	val := input[i].Value
	val[_] == denyList[_]
}

deny[res] {
	failPortCheck
	msg := "Specify Port to SSH into the container"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
