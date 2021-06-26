package appshield.dockerfile.DS003

test_entry_point_negative_empty {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": []}]}}
	count(r) == 0
}

test_entry_point_positive_apt_install {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt install"]}]}}
	count(r) > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_entry_point_positive_apt_get_install {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get install"]}]}}
	r > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_entry_point_positive_apt_get_update {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get update"]}]}}
	count(r) > 0
	startswith(r[_].msg, "Clean apt cache")
}

test_entry_point_negative_apt_install {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt install", "apt-get clean"]}]}}
	count(r) == 0
}

test_entry_point_negative_apt_get_update {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["apt-get update", "apt clean"]}]}}
	count(r) == 0
}
