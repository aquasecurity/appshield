package appshield.kubernetes.KSV027

test_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-proc-mount"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
			"securityContext": {"procMount": "Unmasked"},
		}]},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-proc-mount' should not set spec.containers[*].securityContext.procMount or spec.initContainers[*].securityContext.procMount"
}

test_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-proc-mount"},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"ports": [{"hostPort": 8080}],
			"securityContext": {},
		}]},
	}

	count(r) == 0
}
