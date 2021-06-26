package appshield.dockerfile.DS003

test_deny_empty_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": []}]}}
	count(r) == 0
}

test_deny_apt_install_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt install"]}]}}
	count(r) > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_deny_apt_get_install_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}
	r > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_deny_apt_get_update_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get update"]}]}}
	count(r) > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_deny_apt_install_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt install", "apt-get clean"]}]}}
	count(r) == 0
}

test_deny_apt_get_update_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get update", "apt clean"]}]}}
	count(r) == 0
}
