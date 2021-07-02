package appshield.DS024

test_denied {
	r := deny with input as {"stages": {"debian": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get dist-upgrade"],
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
	r[_] == "apt-get update && apt-get dist-upgrade shouldn't be used in dockerfile"
}

test_shortflag_denied {
	r := deny with input as {"stages": {"debian": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get -q dist-upgrade"],
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
	r[_] == "apt-get update && apt-get -q dist-upgrade shouldn't be used in dockerfile"
}

test_longflag_denied {
	r := deny with input as {"stages": {"debian": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get --quiet dist-upgrade"],
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
	r[_] == "apt-get update && apt-get --quiet dist-upgrade shouldn't be used in dockerfile"
}

test_allowed {
	r := deny with input as {"stages": {"debian": [
		{
			"Cmd": "from",
			"Value": ["debian"],
		},
		{
			"Cmd": "run",
			"Value": ["apt-get update && apt-get upgrade"],
		},
		{
			"Cmd": "cmd",
			"Value": [
				"python",
				"/usr/src/app/app.py",
			],
		},
	]}}

	count(r) == 0
}
