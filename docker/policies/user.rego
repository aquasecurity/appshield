package appshield.dockerfile.DS002

__rego_metadata__ := {
	"id": "DS002",
	"title": "Image user should not be 'root'",
	"version": "v1.0.0",
	"severity": "High",
	"type": "Dockerfile Security Check",
	"description": "It is a good practice to run the container as a non-root user.",
	"recommended_actions": "Add 'USER <non root user name>' line to the Dockerfile",
}

# getUser returns all the usernames from
# the USER command.
getUser[user] {
  some i
  input.stages[name][i].Cmd == "user"
  val := input.stages[name][i].Value
  user := val[_]
}

# failUserCount is true if there is no USER command.
failUserCount {
	count(getUser) < 1
}

# failLastUserRoot is true if the last USER command
# value is "root"
failLastUserRoot {
	user := cast_array(getUser)
	len := count(getUser)
	user[minus(len, 1)] == "root"
}

deny[msg] {
	failUserCount
	msg = "Specify at least 1 USER command in Dockerfile"
}

deny[res] {
	failLastUserRoot
	msg := "Last USER command in Dockerfile should not be root"
	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
