package appshield.dockerfile.DS004

# Test EXPOSE with PORT 22
test_deny_port_22_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "EXPOSE", "Value": [22]}]}}
	count(r) > 0
	startswith(r[_].msg, "Specify Port to SSH into the container")
}

# Test EXPOSE without PORT 22
test_deny_no_port_22_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "EXPOSE", "Value": [8080]}]}}
	count(r) == 0
}
