package appshield.kubernetes.KSV028

test_denied {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-volume-types"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{
				"name": "volume-a",
				"scaleIO": {
					"gateway": "https://localhost:443/api",
					"system": "scaleio",
					"protectionDomain": "sd0",
					"storagePool": "sp1",
					"volumeName": "vol-a",
					"secretRef": {"name": "sio-secret"},
					"fsType": "xfs",
				},
			}],
		},
	}

	count(r) == 1
	r[_].msg == "Pod 'hello-volume-types' should set 'spec.volumes[*]' to type 'PersistentVolumeClaim'"
}

test_allowed {
	r := deny with input as {
		"apiVersion": "v1",
		"kind": "Pod",
		"metadata": {"name": "hello-volume-types"},
		"spec": {
			"containers": [{
				"command": [
					"sh",
					"-c",
					"echo 'Hello' && sleep 1h",
				],
				"image": "busybox",
				"name": "hello",
			}],
			"volumes": [{"name": "volume-a"}],
		},
	}

	count(r) == 0
}
