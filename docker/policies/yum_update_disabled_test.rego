package appshield.DS008

test_deny_update_to_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum update-to"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use yum update-to")
}

test_deny_update_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum update"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use yum update")
}

test_deny_upgrade_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use yum upgrade")
}

test_deny_upgrade_to_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum upgrade-to"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use yum upgrade-to")
}

test_deny_not_related_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
