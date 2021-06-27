package appshield.DS003

import data.lib.docker

__rego_metadata__ := {
	"id": "DS003",
	"title": "Clean APT cache",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "It is a good practice to clean the APT cache.",
	"recommended_actions": "Add 'RUN apt-get clean' line to the Dockerfile",
}

__rego_input__ := {
	"combine": "false",
	"selector": [{"type": "dockerfile"}],
}

# run_apt is true if there is `apt` command.
run_apt {
	run := docker.run[_]
	re_match(`\bapt\b`, run.Value[_])
}

# apt_clean_cache is true if there is an apt-get clean
# command.
apt_clean_cache {
	run := docker.run[_]
	re_match(`apt clean|apt-get clean`, run.Value[_])
}

# fail_apt_clean_cache is true if apt-get clean
# is included.
fail_apt_clean_cache {
	run_apt
	not apt_clean_cache
}

deny[res] {
	fail_apt_clean_cache
	res := "Clean apt cache"
}
