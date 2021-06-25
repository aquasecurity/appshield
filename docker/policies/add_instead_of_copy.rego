package appshield.DS005

__rego_metadata__ := {
	"id": "DS005",
	"title": "COPY Instead of ADD",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "Should use COPY instead of ADD unless, running a tar file",
	"recommended_actions": "Replace ADD by COPY",
	"url": "https://docs.docker.com/engine/reference/builder/#add",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

getAdd[args] {
	some i
	input[i].Cmd == "add"

	merged := concat(" ", input[i].Value)

	not contains(merged, ".tar")

	args := merged
}

failAdd {
	count(getAdd) > 0
}

deny[res] {
	failAdd
	args := getAdd[_]
	res := sprintf("expected COPY %s instead of ADD %s", [args, args])
}
