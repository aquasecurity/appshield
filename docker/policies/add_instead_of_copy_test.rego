package appshield.DS005


test_entry_point_positive_mixed_commands {
	r := deny with input as {"stages": {"foo":[
		{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
		{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
	]}}

	count(r) == 1
	startswith(r[_], "expected COPY")
}


test_entry_point_positive_add_command {
	r := deny with input as {"stages": {"foo":[{"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]}]}}

	count(r) > 0
	startswith(r[_], "expected COPY")
}

test_entry_point_negative_other_command {
	r := deny with input as {"stages": {"foo":[{"Cmd": "run", "Value": ["tar -xjf /temp/package.file.tar.gz"]}]}}

	count(r) == 0
}
test_entry_point_negative_copy_command {
	r := deny with input as {"stages": {"foo":[{"Cmd": "copy", "Value": ["test.txt", "test2.txt"]}]}}

	count(r) == 0
}

test_entry_point_negative_add_with_archive_command {
	r := deny with input as {"stages": {"foo":[{"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]}]}}

	count(r) == 0
}

