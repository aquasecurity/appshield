package appshield.dockerfile.DS014

import data.lib.docker

__rego_metadata__ := {
	"id": "DS014",
	"title": "Run using 'wget' and 'curl'",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Dockerfile Security Check",
	"description": "Shouldn't use both 'wget' and 'curl' since they are two tools that have the same effect",
	"recommended_actions": "Pick one util",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

deny[res] {
	wget := get_tool_usage(docker.run[_], "wget")
	curl := get_tool_usage(docker.run[_], "curl")

	count(wget) > 0
	count(curl) > 0

	res := "Shouldn't use both curl and wget"
}

# chained commands
# e.g. RUN curl http://example.com
get_tool_usage(cmd, cmd_name) = r {
	count(cmd.Value) == 1

	commands_list = split(cmd.Value[0], "&&")

	reg_exp = sprintf("^( )*%s", [cmd_name])

	r := [x |
		instruction := commands_list[_]

		#install is allowed (it may be required by installed app)
		not contains(instruction, "install ")
		regex.match(reg_exp, instruction)
		x := cmd.Value[0]
	]
}

# JSON array is specified
# e.g. RUN ["curl", "http://example.com"]
get_tool_usage(cmd, cmd_name) = res {
	count(cmd.Value) > 1

	cmd.Value[0] == cmd_name

	res := [concat(" ", cmd.Value)]
}
