package appshield.kubernetes.KSV029

test_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
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

test_pod_run_as_group_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"runAsGroup": 0},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}

test_pod_run_as_group_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"runAsGroup": 10001},
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

	count(r) == 0
}

test_pod_supplemental_groups_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"supplementalGroups": {"rule": "RunAsAny"}},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}

test_pod_fs_group_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-run-as-group"},
		"spec": {
			"securityContext": {"fsGroup": {"rule": "RunAsAny"}},
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
	r[_].msg == "Pod 'hello-run-as-group' should set 'spec.securityContext.runAsGroup', 'spec.securityContext.supplementalGroups[*]' and 'spec.securityContext.fsGroup' to integer greater than 0"
}
