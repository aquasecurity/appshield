package appshield.DS008

__rego_metadata__ := {
	"id": "DS008",
	"title": "Yum Update Enabled",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "Yum update is being used",
	"recommended_actions": "Don't install unnecessary packages or run 'updates' (yum update) that downloads many files to a new image layer.",
	"url": "https://docs.docker.com/engine/install/centos/#upgrade-docker-engine-1",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

getUpdate[args] {
	some i
	input[i].Cmd == "run"

	merged := concat(" ", input[i].Value)

	regex.match("(yum update)|(yum update-to)|(yum upgrade)|(yum upgrade-to)", merged)

	args := merged
}

failUpdate {
	count(getUpdate) > 0
}

deny[res] {
	failUpdate
	args := getUpdate[_]
	res := sprintf("Shouldn't use %s in Dockerfile", [args])
}
