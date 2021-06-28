package appshield.DS0010

import data.lib.docker

__rego_metadata__ := {
	"id": "DS0010",
	"title": "Wokrdir path not absolute",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Dockerfile Security Check",
	"description": "Workdir path is not absolute.",
	"recommended_actions": "Workdir path should be absolute",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# workdir_path_not_absolute is true if the path starts with anything else than /
workdir_path_not_absolute {
	path := docker.workdir[_]
	not regex.match("(^/[A-z0-9-_+]*)|(^[A-z0-9-_+]:\\\\.*)|(^\\$[{}A-z0-9-_+].*)", path.Value[0])
}

deny[res] {
	workdir_path_not_absolute
	res := "Workdir path should be absolute"
}
