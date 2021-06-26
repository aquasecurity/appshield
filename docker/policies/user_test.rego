package appshield.dockerfile.DS002

test_deny_not_empty_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["user1", "user2"]}]}}

	count(r) == 0
}

test_deny_is_root_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["user1", "root"]}]}}

	count(r) > 0
	startswith(r[_].msg, "Last USER command in Dockerfile should not be root")
}

test_deny_not_root_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["root", "user2"]}]}}

	count(r) == 0
}

test_deny_no_user_cmd_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "expose", "Value": [22]}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}

test_deny_empty_user_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": []}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}
