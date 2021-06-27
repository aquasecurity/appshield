package appshield.dockerfile.DS004

# Test EXPOSE with PORT 22
test_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "EXPOSE", "Value": [22]}]}}
	count(r) > 0
	startswith(r[_].msg, "Specify Port to SSH into the container")
}

# Test EXPOSE without PORT 22
test_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "EXPOSE", "Value": [8080]}]}}
	count(r) == 0
}
