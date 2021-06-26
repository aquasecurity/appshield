package appshield.DS006

test_entry_point_positive_upgrade {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use apt-get upgrade")
}

test_entry_point_positive_dist_upgrade {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get dist-upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use apt-get dist-upgrade")
}

test_entry_point_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
