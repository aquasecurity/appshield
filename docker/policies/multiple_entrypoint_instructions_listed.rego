package appshield.DS007

__rego_metadata__ := {
	"id": "DS007",
	"title": "Multiple ENTRYPOINT Instructions Listed",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "There can only be one ENTRYPOINT instruction in a Dockerfile. Only the last ENTRYPOINT instruction in the Dockerfile will have an effect",
	"recommended_actions": "Remove unnecessary ENTRYPOINT instruction.",
	"url": "https://docs.docker.com/engine/reference/builder/#entrypoint",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

get_entrypoints(image) = entrypoints {
	entrypoints := [v | image[i].Cmd == "entrypoint"; v := concat(" ", image[i].Value)]
}

deny[res] {
	args := get_entrypoints(input.stages[_])
	count(args) > 1
	res := sprintf("There are %d duplicate ENTRYPOINT instructions", [count(args)])
}
