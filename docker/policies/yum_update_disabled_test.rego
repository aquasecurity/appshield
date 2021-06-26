package appshield.DS008

test_deny_update_to_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["yum update-to"]}]}}
	count(r) > 0
	r[_] == "Shouldn't use yum update-to in Dockerfile"
}

test_deny_update_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["yum update"]}]}}
	count(r) > 0
	r[_] == "Shouldn't use yum update in Dockerfile"
}

test_deny_upgrade_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["yum upgrade"]}]}}

	count(r) > 0
	r[_] == "Shouldn't use yum upgrade in Dockerfile"
}

test_deny_upgrade_to_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["yum upgrade-to"]}]}}

	count(r) > 0
	r[_] == "Shouldn't use yum upgrade-to in Dockerfile"
}

test_deny_not_related_negative {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get install"]}]}}

	count(r) == 0
}
