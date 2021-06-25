package appshield.dockerfile.DS001

# Test FROM image with latest tag
test_failLatest_latest_tag {
	failLatest with input as {"command": {"openjdk": [{"Cmd": "from", "Value": ["openjdk:latest"]}]}}
}

# Test FROM image with no tag
test_failLatest_no_tag {
	failLatest with input as {"command": {"openjdk": [{"Cmd": "from", "Value": ["openjdk"]}]}}
}

# Test FROM with scratch
test_failLatest_scratch {
	not failLatest with input as {"command": {"scratch": [{"Cmd": "from", "Value": ["scratch"]}]}}
}
