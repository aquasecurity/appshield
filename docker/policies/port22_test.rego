package appshield.dockerfile.DS004

# Test EXPOSE with PORT 22
test_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{
		"Cmd": "expose",
		"Value": ["22"],
	}]}}

	count(r) > 0
	startswith(r[_], "Port 22 is exposed via the Dockerfile")
}

test_tcp_denied {
	r := deny with input as {"stages": {"alpine:3.13": [{
		"Cmd": "expose",
		"Value": ["22/tcp"],
	}]}}

	count(r) > 0
	startswith(r[_], "Port 22 is exposed via the Dockerfile")
}

# Test EXPOSE without PORT 22
test_allowed {
	r := deny with input as {"stages": {"alpine:3.13": [{
		"Cmd": "expose",
		"Value": ["8080"],
	}]}}

	count(r) == 0
}
