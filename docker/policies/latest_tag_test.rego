package appshield.DS001

# Test FROM image with latest tag
test_latest_tag_denied {
	r := deny with input as {"stages": {"openjdk": [{"Cmd": "from", "Value": ["openjdk:latest"]}]}}
	count(r) == 1
	r[_] == "Specify tag for image openjdk"
}

# Test FROM image with no tag
test_no_tag_denied {
	r := deny with input as {"stages": {"openjdk": [{"Cmd": "from", "Value": ["openjdk"]}]}}
	count(r) == 1
	r[_] == "Specify tag for image openjdk"
}

# Test FROM with scratch
test_scratch_allowed {
	r := deny with input as {"stages": {"scratch": [{
		"Cmd": "from",
		"Value": ["scratch"],
	}]}}

	count(r) == 0
}

test_multi_stage_allowed {
	r := deny with input as {"stages": {
		"golang:1.15 as builder": [
			{
				"Cmd": "from",
				"Value": ["golang:1.15", "as", "builder"],
			},
			{
				"Cmd": "run",
				"Value": ["apt-get update"],
			},
		],
		"alpine:3.13": [{
			"Cmd": "from",
			"Value": ["alpine:3.13"],
		}],
	}}

	count(r) == 0
}
