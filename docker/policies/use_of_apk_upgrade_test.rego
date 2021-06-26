package appshield.DS013

test_deny_basic_positive {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.7"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update     && apk upgrade     && apk add kubectl=1.20.0-r0     && rm -rf /var/cache/apk/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["kubectl"],
		},
		{
			"Cmd": "from",
			"Value": ["alpine:3.9"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update && apk upgrade && apk add kubectl=1.20.0-r0     && rm -rf /var/cache/apk/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["kubectl"],
		},
	]}}

	count(r) == 2
	startswith(r[_], "Shouldn't use apk update")
}

test_deny_basic_negative {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.3": [
		{
			"Cmd": "from",
			"Value": ["alpine:3.7"],
		},
		{
			"Cmd": "run",
			"Value": ["apk update     && apk add kubectl=1.20.0-r0     && rm -rf /var/cache/apk/*"],
		},
		{
			"Cmd": "entrypoint",
			"Value": ["kubectl"],
		},
	]}}

	count(r) == 0
}
