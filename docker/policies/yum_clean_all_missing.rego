package appshield.DS015

import data.lib.docker

__rego_metadata__ := {
	"id": "DS015",
	"title": "Yum Clean All Missing",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Need to use 'yum clean all' after using a 'yum install' command to clean package cached data and reduce image size",
	"recommended_actions": "Add 'yum clean all' to Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

get_yum[arg] {
	run := docker.run[_]
	arg := run.Value[0]

	regex.match("yum (-[a-zA-Z]+ *)*install", arg)

	not contains_clean_after_yum(arg)
}

deny[res] {
	args := get_yum[_]
	res := sprintf("'yum clean all' is missed: %s", [args])
}

contains_clean_after_yum(cmd) {
	yum_install_command := regex.find_n("yum (-[a-zA-Z]+ *)*install", cmd, -1)

	install := indexof(cmd, yum_install_command[0])
	install != -1

	clean := indexof(cmd, "yum clean all")
	clean != -1

	install < clean
}
