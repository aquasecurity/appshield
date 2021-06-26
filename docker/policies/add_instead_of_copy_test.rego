package appshield.DS005

test_deny_mixed_commands_positive {
	r := deny with input as {"stages": {"foo": [
		{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
		{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
	]}}

	count(r) == 1
	startswith(r[_], "expected COPY")
}

test_deny_add_command_positive {
	r := deny with input as {"stages": {"foo": [{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}]}}

	count(r) > 0
	startswith(r[_], "expected COPY")
}

test_deny_other_command_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}]}}

	count(r) == 0
}

test_deny_command_negative_copy {
	r := deny with input as {"stages": {"foo": [{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}]}}

	count(r) == 0
}

test_deny_add_with_archive_command_negative {
	r := deny with input as {"stages": {"foo": [{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]}]}}

	count(r) == 0
}
