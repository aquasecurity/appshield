package appshield.DS008

test_entry_point_positive_update_to {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum update-to"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use yum update-to")
}

test_entry_point_positive_update {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum update"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use yum update")
}

test_entry_point_positive_upgrade {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use yum upgrade")
}

test_entry_point_positive_upgrade_to {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["yum upgrade-to"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use yum upgrade-to")
}

test_entry_point_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
