package appshield.DS006

test_deny_upgrade_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get upgrade"]}]}}

	count(r) > 0
	r[_] == "Shouldn't use apt-get upgrade in Dockerfile"
}

test_deny_dist_upgrade_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get dist-upgrade"]}]}}

	count(r) > 0
	r[_] == "Shouldn't use apt-get dist-upgrade in Dockerfile"
}

test_deny_basic_negative {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
