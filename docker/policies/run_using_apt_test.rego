package appshield.DS009

# Test RUN using APT
test_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["apt install"]}]}}
	count(r) == 1
	startswith(r[_], "Remove apt from run command")
}

# Test RUN without using APT
test_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["yum install"]}]}}
	count(r) == 0
}
