package appshield.DS012

test_deny_update_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["dnf update"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use dnf update")
}

test_deny_upgrade_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["dnf upgrade"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use dnf upgrade")
}

test_deny_upgrade_minimal_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["dnf upgrade-minimal"]}]}}
	count(r) > 0
	startswith(r[_], "Shouldn't use dnf upgrade-minimal")
}

test_deny_not_related_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["dnf install -y nginx   \t&& dnf clean all   \t&& rm -rf /var/cache/yum"]}]}}

	count(r) == 0
}
