package appshield.dockerfile.DS002

import data.lib.docker

__rego_metadata__ := {
	"id": "DS002",
	"title": "Image user should not be 'root'",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Running containers with 'root' user can lead to container escape situation. It is a best practice to run containers as non-root users, which can be done by adding 'USER' statement to the Dockerfile.",
	"recommended_actions": "Add 'USER <non root user name>' line to the Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# get_user returns all the usernames from
# the USER command.
get_user[username] {
	user := docker.user[_]
	username := user.Value[_]
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
	msg = "Specify at least 1 USER command in Dockerfile with non-root user as argument"
}

deny[res] {
	fail_last_user_root
	res := "Last USER command in Dockerfile should not be root"
}
package appshield.dockerfile.DS002

import data.lib.docker

__rego_metadata__ := {
	"id": "DS002",
	"title": "Image user should not be 'root'",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Dockerfile Security Check",
	"description": "Running containers with 'root' user can lead to container escape situation. It is a best practice to run containers as non-root users, which can be done by adding 'USER' statement to the Dockerfile.",
	"recommended_actions": "Add 'USER <non root user name>' line to the Dockerfile",
	"url": "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "dockerfile"}],
}

# get_user returns all the usernames from
# the USER command.
get_user[username] {
	user := docker.user[_]
	username := user.Value[_]
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
	msg = "Specify at least 1 USER command in Dockerfile with non-root user as argument"
}

deny[res] {
	fail_last_user_root
	res := "Last USER command in Dockerfile should not be root"
}
