package appshield.DS005

test_failAdd_basic {
	not failAdd with input as  {"command": {"foo":[{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}]}}
}

test_failAdd_copy {
	not failAdd with input as {"command": {"foo":[{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}]}}
}

test_failAdd_add {
	failAdd with input as {"command": {"foo":[{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}]}}
}

test_failAdd_many_add {
	failAdd with input as {"command": {"foo":[
		{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
		{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
	]}}
}

test_failAdd_add_archive {
	not failAdd with input as {"command": {"foo":[{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]}]}}
}

test_entry_point_positive {
	r := deny with input as {"command": {"foo":[{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}]}}

	count(r) > 0
	startswith(r[_], "expected COPY")
}

test_entry_point_negative {
	r := deny with input as {"command": {"foo":[{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}]}}

	count(r) == 0
}
