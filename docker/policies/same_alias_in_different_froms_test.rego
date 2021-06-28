package appshield.DS012

test_deny_basic_positive {
	r := deny with input as {"stages": {
		"baseImage as bi": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	startswith(r[_], "Duplicate alias found among")
}

test_deny_no_alias_positive {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	startswith(r[_], "Duplicate alias found among")
}

test_deny_extra_spaces_positive {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as    build": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 1
	startswith(r[_], "Duplicate alias found among")
}

test_deny_basic_negative {
	r := deny with input as {"stages": {
		"baseImage": [
			{
				"Cmd": "from",
				"Value": ["baseImage"],
			},
			{
				"Cmd": "run",
				"Value": ["Test"],
			},
		],
		"debian:jesse2 as build2": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse2",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["stuff"],
			},
		],
		"debian:jesse1 as build1": [
			{
				"Cmd": "from",
				"Value": [
					"debian:jesse1",
					"as",
					"build",
				],
			},
			{
				"Cmd": "run",
				"Value": ["more_stuff"],
			},
		],
	}}

	count(r) == 0
}
