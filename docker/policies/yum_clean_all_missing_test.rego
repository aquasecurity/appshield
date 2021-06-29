package appshield.DS015

test_basic_denied {
	r := deny with input as {"stages": {
		"alpine:3.5": [
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
				"Value": ["yum install"],
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
		],
		"alpine:3.4": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install yum clean all"],
			},
		],
	}}

	count(r) == 1
	r[_] == "'yum clean all' is missed: yum install"
}

test_wrong_order_of_commands_denied {
	r := deny with input as {"stages": {"alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.5"],
		},
		{
			"Cmd": "run",
			"Value": ["yum clean all     yum -y install"],
		},
	]}}

	count(r) == 1
	r[_] == "'yum clean all' is missed: yum clean all     yum -y install"
}

test_basic_allowed {
	r := deny with input as {"stages": {
		"alpine:3.5": [
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
				"Value": ["yum install     yum clean all"],
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
		],
		"alpine:3.4": [
			{
				"Cmd": "from",
				"Value": ["alpine:3.4"],
			},
			{
				"Cmd": "run",
				"Value": ["yum -y install     yum clean all"],
			},
		],
	}}

	count(r) == 0
}
