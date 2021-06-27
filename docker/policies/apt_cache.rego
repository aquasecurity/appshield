package appshield.dockerfile.DS003

__rego_metadata__ := {
	"id": "DS003",
	"title": "Clean APT cache",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "It is a good practice to clean the APT cache.",
	"recommended_actions": "Add 'RUN apt-get clean' line to the Dockerfile",
}

# runs_apt is true if there is `apt` command.
runs_apt {
	some i, name
	input.stages[name][i].Cmd == "run"
	val := input.stages[name][i].Value[_]
	re_match(`\bapt\b`, val)
}

# apt_clean_cache is true if there is an apt-get clean
# command.
apt_clean_cache {
	some i
	input.stages[name][i].Cmd == "run"
	val := input.stages[name][i].Value[_]
	re_match(`apt clean|apt-get clean`, val)
}

# fail_apt_clean_cache is true if apt-get clean
# is included.
fail_apt_clean_cache {
	runs_apt
	not apt_clean_cache
}

deny[res] {
	fail_apt_clean_cache
	msg := "Clean apt cache"

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
