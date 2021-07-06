package appshield.dockerfile.DS018

test_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=builder2"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 1
	r[_] == "Invalid alias: --from=builder2"
}

test_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=dep"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}

test_stage_index_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3 as dep": [
			{
				"Cmd": "from",
				"Value": [
					"golang:1.7.3",
					"AS",
					"builder",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "copy",
				"Flags": ["--from=0"],
				"Value": [
					"/go/src/github.com/alexellis/href-counter/app",
					".",
				],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
	}}

	count(r) == 0
}
