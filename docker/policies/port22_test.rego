package appshield.dockerfile.DS004

# Test EXPOSE with PORT 22
test_entry_point_positive_port_22 {
	r := deny with input as {"stages": {"foo": [{"Cmd": "EXPOSE", "Value": [22]}]}}
	count(r) > 0
	startswith(r[_].msg, "Specify Port to SSH into the container")
}

# Test EXPOSE without PORT 22
test_entry_point_negative_no_port_22 {
	r := deny with input as {"stages": {"foo": [{"Cmd": "EXPOSE", "Value": [8080]}]}}
	count(r) == 0
}
