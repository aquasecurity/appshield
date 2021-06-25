package appshield.DS009

test_entry_point_positive {
	r := deny with input as {"stages": {
		"golang": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8000",
				],
			},
		],
		"alpine": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
	}}

	count(r) == 2
	startswith(r[_], "Duplicate ENTRYPOINT")
}

test_entry_point_negative {
	r := deny with input as {"stages": {
		"golang": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
		"alpine": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "entrypoint",
				"Value": [
					"/opt/app/run.sh",
					"--port",
					"8080",
				],
			},
		],
	}}

	count(r) == 0
}
