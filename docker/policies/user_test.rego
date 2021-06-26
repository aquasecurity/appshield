package appshield.dockerfile.DS002

test_entry_point_negative_not_empty {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["user1", "user2"]}]}}

	count(r) == 0
}

test_entry_point_positive_is_root {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["user1", "root"]}]}}

	count(r) > 0
	startswith(r[_].msg, "Last USER command in Dockerfile should not be root")
}

test_entry_point_negative_not_root {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": ["root", "user2"]}]}}

	count(r) == 0
}

test_entry_point_positive_no_user_cmd {
	r := deny with input as {"stages": {"foo": [{"Cmd": "expose", "Value": [22]}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}

test_entry_point_positive_empty_user {
	r := deny with input as {"stages": {"foo": [{"Cmd": "user", "Value": []}]}}

	count(r) == 1
	startswith(r[_], "Specify at least 1 USER command in Dockerfile")
}
