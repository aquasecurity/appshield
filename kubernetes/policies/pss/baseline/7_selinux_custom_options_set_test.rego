package appshield.kubernetes.KSV025

test_pod_invalid_selinux_type_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "custom"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privileged' should not set host ports, 'ports[*].hostPort'"
}

test_pod_invalid_key_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {"type": "container_t", "role": "admin"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privileged' should not set host ports, 'ports[*].hostPort'"
}

test_empty_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {
			"securityContext": {"seLinuxOptions": {}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-privileged' should not set host ports, 'ports[*].hostPort'"
}

test_undefined_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-selinux"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}
