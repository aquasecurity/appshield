package appshield.dockerfile.DS003

test_failAPTCleanCache_empty {
	not failAPTCleanCache with input as [{"Cmd": "run", "Value": []}]
}

test_failAPTCleanCache_apt_install {
	failAPTCleanCache with input as [{"Cmd": "run", "Value": ["apt install"]}]
}

test_failAPTCleanCache_apt_get_install {
	failAPTCleanCache with input as [{"Cmd": "run", "Value": ["apt-get install"]}]
}

test_failAPTCleanCache_apt_get_update {
	failAPTCleanCache with input as [{"Cmd": "run", "Value": ["apt-get update"]}]
}

test_failAPTCleanCache_apt_install {
	not failAPTCleanCache with input as [{"Cmd": "run", "Value": ["apt install", "apt-get clean"]}]
}

test_failAPTCleanCache_apt_get_update {
	not failAPTCleanCache with input as [{"Cmd": "run", "Value": ["apt-get update", "apt clean"]}]
}
