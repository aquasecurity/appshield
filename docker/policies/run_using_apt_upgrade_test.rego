package appshield.DS006

test_failUpgrage_basic {
	failUpgrade with input as [{"Cmd": "run", "Value": ["apt-get upgrade"]}]
}

test_failUpgrage_dist {
	failUpgrade with input as [{"Cmd": "run", "Value": ["apt-get dist-upgrade"]}]
}

test_entry_point_positive {
	r := deny with input as [{"Cmd": "run", "Value": ["apt-get dist-upgrade"]}]

	count(r) > 0
	startswith(r[_], "Shouldn't use apt-get dist-upgrade")
}

test_entry_point_negative {
	r := deny with input as [{"Cmd": "run", "Value": ["apt-get install"]}]

	count(r) == 0
}
