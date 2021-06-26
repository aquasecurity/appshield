package appshield.DS015

test_deny_basic_positive {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["node:carbon2"],
		},
		{
			"Cmd": "copy",
			"Value": ["package.json", "yarn.lock", "my_app"],
		},
	]}}

	count(r) == 1
	startswith(r[_], "Slash is expected at the end of my_app")
}

test_deny_two_arg_negative {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["node:carbon2"],
		},
		{
			"Cmd": "copy",
			"Value": ["package.json", "yarn.lock"],
		},
	]}}

	count(r) == 0
}

test_deny_three_arg_negative {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["node:carbon2"],
		},
		{
			"Cmd": "copy",
			"Value": ["package.json", "yarn.lock", "myapp/"],
		},
	]}}

	count(r) == 0
}
