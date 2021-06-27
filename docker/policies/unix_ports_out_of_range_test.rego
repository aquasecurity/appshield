package appshield.DS008

test_deny_65536_positive {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["gliderlabs/alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
		{
			"Cmd": "expose",
			"Value": [
				"65536/tcp",
				"80",
				"443",
				"22",
			],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"nginx",
				"-g",
				"daemon off;",
			],
		},
	]}}

	count(r) == 1
	r[_] == "'EXPOSE' contains port which is out of range [0, 65535]: 65536"
}

test_deny_within_range_negative {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["gliderlabs/alpine:3.3"],
		},
		{
			"Cmd": "run",
			"Value": ["apk --no-cache add nginx"],
		},
		{
			"Cmd": "expose",
			"Value": [
				"65530/tcp",
				"80",
				"443",
				"22",
			],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"nginx",
				"-g",
				"daemon off;",
			],
		},
	]}}

	count(r) == 0
}
