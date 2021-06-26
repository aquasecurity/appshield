package appshield.dockerfile.DS004

# Test EXPOSE with PORT 22
test_failPortCheck_port_22 {
	failPortCheck with input as [{"Cmd": "EXPOSE", "Value": [22]}]
}

# Test EXPOSE without PORT 22
test_failPortCheck_no_port_22 {
	failPortCheck with input as [{"Cmd": "EXPOSE", "Value": [8080]}]
}
