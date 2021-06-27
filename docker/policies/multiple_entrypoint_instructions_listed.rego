package appshield.DS007

__rego_metadata__ := {
	"id": "DS009",
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

get_entry_points(image) = r {
	r := [i | image[j].Cmd == "entrypoint"; vals := image[j].Value; i := concat(" ", vals)]
}

fail_entry_points {
	count(get_entry_points(input.stages[_])) > 1
}

deny[res] {
	fail_entry_points
	args := get_entry_points(input.stages[_])
	res := sprintf("Duplicate ENTRYPOINT %s in Dockerfile", [args])
}
