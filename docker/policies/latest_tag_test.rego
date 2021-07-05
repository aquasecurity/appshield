package appshield.dockerfile.DS001

test_allowed {
	r := deny with input as {"stages": {"openjdk:8u292-oracle": [{"Cmd": "from", "Value": ["openjdk:8u292-oracle"]}]}}
	count(r) == 0
}

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

test_with_variables_allowed {
	r := deny with input as {"stages": {
		"alpine:3.5": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=alpine:3.12"],
			},
		],
		"image": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		],
	}}

	count(r) == 0
}

test_with_variables_denied {
	r := deny with input as {"stages": {
		"alpine:3.5": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.5"],
			},
			{
				"Cmd": "arg",
				"Value": ["IMAGE=all-in-one"],
			},
		],
		"image": [
			{
				"Cmd": "from",
				"Value": ["$IMAGE"],
			},
			{
				"Cmd": "cmd",
				"Value": [
					"python",
					"/usr/src/app/app.py",
				],
			},
		],
	}}

	count(r) == 1
	r[_] == "Specify tag for image all-in-one"
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
