package appshield.DS017

test_denied {
	r := deny with input as {"stages": {
		"golang:1.7.3": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "workdir",
				"Value": ["/go/src/github.com/alexellis/href-counter/"],
			},
			{
				"Cmd": "run",
				"Value": ["go get -d -v golang.org/x/net/html"],
			},
			{
				"Cmd": "copy",
				"Value": [
					"app.go",
					".",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
			{
				"Cmd": "cmd",
				"Value": ["./apps"],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "run",
				"Value": ["apk --no-cache add ca-certificates"],
			},
			{
				"Cmd": "workdir",
				"Value": ["/root/"],
			},
			{
				"Cmd": "copy",
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
	r[_] == "There are 2 duplicate CMD instructions"
}

test_allowed {
	r := deny with input as {"stages": {
		"golang:1.7.3": [
			{
				"Cmd": "from",
				"Value": ["golang:1.7.3"],
			},
			{
				"Cmd": "workdir",
				"Value": ["/go/src/github.com/alexellis/href-counter/"],
			},
			{
				"Cmd": "run",
				"Value": ["go get -d -v golang.org/x/net/html"],
			},
			{
				"Cmd": "copy",
				"Value": [
					"app.go",
					".",
				],
			},
			{
				"Cmd": "run",
				"Value": ["CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app ."],
			},
			{
				"Cmd": "cmd",
				"Value": ["./app"],
			},
		],
		"alpine:latest": [
			{
				"Cmd": "from",
				"Value": ["alpine:latest"],
			},
			{
				"Cmd": "run",
				"Value": ["apk --no-cache add ca-certificates"],
			},
			{
				"Cmd": "workdir",
				"Value": ["/root/"],
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
