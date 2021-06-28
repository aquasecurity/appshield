package appshield.DS010

test_deny_basic_positive {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "run",
			"Value": ["sudo pip install --upgrade pip"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"requirements.txt",
				"/usr/src/app/",
			],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --no-cache-dir -r /usr/src/app/requirements.txt"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"app.py",
				"/usr/src/app/",
			],
		},
		{
			"Cmd": "copy",
			"Value": [
				"templates/index.html",
				"/usr/src/app/templates/",
			],
		},
		{
			"Cmd": "expose",
			"Value": ["5000"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}}

	count(r) == 1
	startswith(r[_], "Shouldn't use sudo pip install --upgrade pip in Dockerfile")
}

test_deny_basic_negative {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["apk add --update py2-pip"],
		},
		{
			"Cmd": "run",
			"Value": ["pip install --upgrade pip"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get install sudo"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"sudoers",
				"/usr/src/app/",
			],
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

	count(r) == 0
}
