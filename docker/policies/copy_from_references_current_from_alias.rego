package appshield.DS007

__rego_metadata__ := {
	"id": "DS007",
	"title": "COPY '--from' references current image FROM alias",
	"version": "v1.0.0",
	"severity": "CRITICAL",
	"type": "Dockerfile Security Check",
	"description": "COPY '--from' should not mention the current FROM alias, since it is impossible to copy from itself",
	"recommended_actions": "Don't use from flag",
	"url": "https://docs.docker.com/develop/develop-images/multistage-build/",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

getAliasFromCopy[args] {
	some i, j, name
	input.stages[name][i].Cmd == "copy"

	cmd := input.stages[name][i]

	contains(cmd.Flags[j], "--from=")
	parts := split(cmd.Flags[j], "=")

	isAliasCurrentFromAlias(name, parts[1])
	args := parts[1]
}

isAliasCurrentFromAlias(currentName, currentAlias) = allow {
	currentNameLower := lower(currentName)
	currentAliasLower := lower(currentAlias)

	#expecting stage name as "myimage:tag as dep"
	parts := split(currentNameLower, " as ")

	parts[1] == currentAlias

	allow = true
}

failFromAlias {
	count(getAliasFromCopy) > 0
}

deny[res] {
	failFromAlias
	args := getAliasFromCopy[_]
	res := sprintf("COPY from shouldn't mention current alias '%s'", [args])
}
