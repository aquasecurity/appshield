package appshield.DS013

test_basic_denied {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["nginx"],
		},
		{
			"Cmd": "env",
			"Value": [
				"AUTHOR",
				"Docker",
			],
		},
		{
			"Cmd": "run",
			"Value": ["cd /usr/share/nginx/html"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"Hello_docker.html",
				"/usr/share/nginx/html",
			],
		},
		{
			"Cmd": "cmd",
			"Value": ["cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'"],
		},
	]}}

	count(r) == 1
	r[_] == "RUN shouldn't be used to change directory: 'cd /usr/share/nginx/html'"
}

test_basic_allowed {
	r := deny with input as {"stages": {"gliderlabs/alpine:3.5": [
		{
			"Cmd": "from",
			"Value": ["nginx"],
		},
		{
			"Cmd": "env",
			"Value": [
				"AUTHOR",
				"Docker",
			],
		},
		{
			"Cmd": "workdir",
			"Value": ["/usr/share/nginx/html"],
		},
		{
			"Cmd": "copy",
			"Value": [
				"Hello_docker.html",
				"/usr/share/nginx/html",
			],
		},
		{
			"Cmd": "cmd",
			"Value": ["cd /usr/share/nginx/html && sed -e s/Docker/\"$AUTHOR\"/ Hello_docker.html > index.html ; nginx -g 'daemon off;'"],
		},
	]}}

	count(r) == 0
}
