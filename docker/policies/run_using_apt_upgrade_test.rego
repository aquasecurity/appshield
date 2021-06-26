package appshield.DS006

test_deny_upgrade_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use apt-get upgrade")
}

test_deny_dist_upgrade_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get dist-upgrade"]}]}}

	count(r) > 0
	startswith(r[_], "Shouldn't use apt-get dist-upgrade")
}

test_deny_basic_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
