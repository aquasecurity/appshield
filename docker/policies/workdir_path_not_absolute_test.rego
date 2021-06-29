package appshield.DS009

test_basic_denied {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{"Cmd": "from", "Value": ["alpine:3.5"]},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "workdir",
			"Value": ["/path/to/workdir"],
		},
		{
			"Cmd": "workdir",
			"Value": ["workdir"],
		},
		{
			"Cmd": "expose",
			"Value": ["5000"],
		},
		{
			"Cmd": "cmd",
			"Value": ["python", "/usr/src/app/app.py"],
		},
	]}}

	count(r) == 1
	r[_] == "Path workdir isn't absolute"
}

test_no_work_dir_allowed {
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

test_absolute_work_dir_allowed {
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
			"Cmd": "workdir",
			"Value": ["/path/to/workdir"],
		},
		{
			"Cmd": "expose",
			"Value": ["65530/tcp", "80", "443", "22"],
		},
		{
			"Cmd": "cmd",
			"Value": ["nginx", "-g", "daemon off;"],
		},
	]}}

	count(r) == 0
}
