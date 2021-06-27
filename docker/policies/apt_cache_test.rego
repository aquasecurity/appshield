package appshield.DS003

test_empty_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": []}]}}
	count(r) == 0
}

test_apt_install_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt install"]}]}}
	count(r) == 1
	r[_] == "Clean apt cache"
}

test_apt_get_install_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get install"]}]}}
	r > 0
	r[_] == "Clean apt cache"
}

test_apt_get_update_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get update"]}]}}
	count(r) == 1
	r[_] == "Clean apt cache"
}

test_apt_install_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt install", "apt-get clean"]}]}}
	count(r) == 0
}

test_apt_get_update_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt-get update", "apt clean"]}]}}
	count(r) == 0
}
