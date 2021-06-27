package appshield.dockerfile.DS002

test_not_root_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "user", "Value": ["user1", "user2"]}]}}

	count(r) == 0
}

test_no_user_cmd_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "expose", "Value": [22]}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}

test_root_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "user", "Value": ["user1", "root"]}]}}

	count(r) > 0
	startswith(r[_].msg, "Last USER command in Dockerfile should not be root")
}

test_empty_user_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "user", "Value": []}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}
