package appshield.dockerfile.DS001

# Test FROM image with latest tag
test_entry_point_positive_latest_tag {
	r := deny with input as {"stages": {"openjdk": [{"Cmd": "from", "Value": ["openjdk:latest"]}]}}
	count(r) == 1
	startswith(r[_].msg, "Specify tag for image")
}

# Test FROM image with no tag
test_entry_point_positive_no_tag {
	r := deny with input as {"stages": {"openjdk": [{"Cmd": "from", "Value": ["openjdk"]}]}}
	count(r) == 1
	startswith(r[_].msg, "Specify tag for image")
}

# Test FROM with scratch
test_failLatest_scratch {
	r := deny with input as {"stages": {"scratch": [{"Cmd": "from", "Value": ["scratch"]}]}}
	count(r) == 0
}
