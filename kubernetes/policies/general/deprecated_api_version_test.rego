package appshield.kubernetes.KSV101

# Check for apiVersion is valid 
test_apiIsUpToDate {
	res := deny with input as {
		"apiVersion": "apps/v1",
		"kind": "Deployment",
		"metadata": {"name": "mongo-deployment"},
		"spec": {"template": {"spec": {
			"containers": [{
				"name": "carts-db",
				"image": "mongo",
				"securityContext": {
					"runAsNonRoot": true,
					"allowPrivilegeEscalation": true,
				},
			}],
			"initContainers": [{
				"name": "init-svc",
				"image": "busybox:1.28",
				"securityContext": {"allowPrivilegeEscalation": false},
			}],
		}}},
	}

	count(res) == 0
}

# Check for old deprecated apiVersion X kind Deployment
test_apiIsDeprecated {
	res := deny with input as {
		"apiVersion": "apps/v1beta2",
		"kind": "Deployment",
		"metadata": {"name": "mongo-deployment"},
		"spec": {"template": {"spec": {
			"containers": [{
				"name": "carts-db",
				"image": "mongo",
				"securityContext": {
					"runAsNonRoot": true,
					"allowPrivilegeEscalation": true,
				},
			}],
			"initContainers": [{
				"name": "init-svc",
				"image": "busybox:1.28",
				"securityContext": {"allowPrivilegeEscalation": false},
			}],
		}}},
	}

	res[_].msg == "mongo-deployment is using deprecated 'apiVersion: apps/v1beta2', it should be 'apiVersion: apps/v1'"
}

# Check for old deprecated apiVersion X kind NetworkPolicy
test_apiIsDeprecatedNetwork {
	res := deny with input as {
		"apiVersion": "extensions/v1beta1",
		"kind": "NetworkPolicy",
		"metadata": {"name": "web-allow-external"},
		"spec": {"template": {"spec": {"podSelector:": [{"matchLabels": {"app": "web"}}]}}},
	}

	res[_].msg == "web-allow-external is using deprecated 'apiVersion: extensions/v1beta1', it should be 'apiVersion: networking.k8s.io/v1'"
}
