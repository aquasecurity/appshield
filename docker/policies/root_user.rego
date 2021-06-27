package appshield.dockerfile.DS002

__rego_metadata__ := {
	"id": "DS002",
	"title": "Image user should not be 'root'",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "It is a good practice to run the container as a non-root user.",
	"recommended_actions": "Add 'USER <non root user name>' line to the Dockerfile",
}

# get_user returns all the usernames from
# the USER command.
get_user[user] {
	some i
	input.stages[name][i].Cmd == "user"
	val := input.stages[name][i].Value
	user := val[_]
}

# fail_user_count is true if there is no USER command.
fail_user_count {
	count(get_user) < 1
}

# fail_last_user_root is true if the last USER command
# value is "root"
fail_last_user_root {
	user := cast_array(get_user)
	len := count(get_user)
	user[minus(len, 1)] == "root"
}

deny[msg] {
	fail_user_count
	msg = "Specify at least 1 USER command in Dockerfile"
}

deny[res] {
	fail_last_user_root
	msg := "Last USER command in Dockerfile should not be root"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
