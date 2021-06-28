package appshield.DS0010

# Test WORKDIR without using absolute path
test_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "workdir", "Value": ["bin"]}]}}
	count(r) == 1
	startswith(r[_], "Workdir path should be absolute")
}

# Test WORKDIR using absolute path
test_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "workdir", "Value": ["/usr/bin"]}]}}
	count(r) == 0
}
