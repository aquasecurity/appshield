package appshield.DS010

test_entry_point_positive {
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
	startswith(r[_], "'EXPOSE' contains port which is out of range [0, 65535]: 65536")
}

test_entry_point_negative {
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
