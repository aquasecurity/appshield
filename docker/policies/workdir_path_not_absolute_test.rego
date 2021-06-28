package appshield.DS009

test_deny_basic_positive {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{"Cmd": "from", "Value": ["alpine:3.5"]},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --upgrade pip"],
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
			"Cmd": "copy",
			"Value": ["requirements.txt", "/usr/src/app/"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
		},
		{
			"Cmd": "copy",
			"Value": ["app.py", "/usr/src/app/"],
		},
		{
			"Cmd": "copy",
			"Value": ["templates/index.html", "/usr/src/app/templates/"],
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
	startswith(r[_], "Path workdir isn't absolute")
}

test_deny_no_work_dir_negative {
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

test_deny_absolute_work_dir_negative {
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
