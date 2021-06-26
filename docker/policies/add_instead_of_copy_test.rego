package appshield.DS005

test_deny_mixed_commands_positive {
	r := deny with input as {"stages": {"alpine:3.13": [
		{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
		{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
	]}}

	count(r) == 1
	r[_] == "expected COPY /target/app.jar app.jar instead of ADD /target/app.jar app.jar"
}

test_deny_add_command_positive {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}]}}

	count(r) > 0
	r[_] == "expected COPY /target/app.jar app.jar instead of ADD /target/app.jar app.jar"
}

test_deny_other_command_negative {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}]}}

	count(r) == 0
}

test_deny_command_negative_copy {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}]}}

	count(r) == 0
}

test_deny_add_with_archive_command_negative {
	r := deny with input as {"stages": {"alpine:3.13": [{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]}]}}

	count(r) == 0
}
