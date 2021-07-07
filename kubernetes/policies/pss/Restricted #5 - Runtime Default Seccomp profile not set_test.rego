package appshield.kubernetes.KSV030

import data.lib.kubernetes

test_pod_context_custom_profile_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "custom"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello AppArmor!' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-apparmor' should set spec.securityContext.seccompProfile.type to 'runtime/default'"
}

test_pod_context_undefined_type_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {
			"securityContext": {"seccompProfile": {}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello AppArmor!' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_pod_context_undefined_profile_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {
			"securityContext": {"seccompProfile": {}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello AppArmor!' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_pod_context_runtime_default_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {
			"securityContext": {"seccompProfile": {"type": "runtime/default"}},
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello AppArmor!' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
		},
	}

	count(r) == 0
}

test_container_context_custom_profile_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello AppArmor!' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {"type": "custom"}},
		}]},
	}

	count(r) == 1
	r[_].msg == "Container 'hello' of Pod 'hello-apparmor' should set spec.containers[*].securityContext.seccompProfile.type to 'runtime/default'"
}

test_container_context_undefined_type_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello AppArmor!' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {}},
		}]},
	}

	count(r) == 0
}

test_container_context_undefined_profile_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello AppArmor!' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
		}]},
	}

	count(r) == 0
}

test_container_context_runtime_default_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {
			"annotations": {"container.apparmor.security.beta.kubernetes.io/hello": "custom"},
			"name": "hello-apparmor",
		},
		"spec": {"containers": [{
			"command": [
				"sh",
				"-c",
				"echo 'Hello AppArmor!' && sleep 1h",
			],
			"image": "busybox",
			"name": "hello",
			"securityContext": {"seccompProfile": {"type": "runtime/default"}},
		}]},
	}

	count(r) == 0
}
