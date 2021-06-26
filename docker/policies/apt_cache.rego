package appshield.dockerfile.DS003

__rego_metadata__ := {
	"id": "DS003",
	"title": "Clean APT cache",
	"version": "v1.0.0",
	"severity": "Medium",
	"type": "Dockerfile Security Check",
	"description": "It is a good practice to clean the APT cache.",
	"recommended_actions": "Add 'RUN apt-get clean' line to the Dockerfile",
}

# runsAPT is true if there is `apt` command.
runs_apt {
	some i, name
	input.stages[name][i].Cmd == "run"
	val := input.stages[name][i].Value[_]
	re_match(`\bapt\b`, val)
}

# APTCleanCache is true if there is an apt-get clean
# command.
APTCleanCache {
	some i
	input.stages[name][i].Cmd == "run"
	val := input.stages[name][i].Value[_]
	re_match(`apt clean|apt-get clean`, val)
}

# failAPTCleanCache is true if apt-get clean
# is included.
failAPTCleanCache {
	runs_apt
	not APTCleanCache
}

deny[res] {
	failAPTCleanCache
	msg := "Clean apt cache"

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
