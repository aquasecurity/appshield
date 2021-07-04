package appshield.kubernetes.KSV010

import data.lib.kubernetes

default failHostPID = false

__rego_metadata__ := {
	"id": "KSV010",
	"title": "Access to host PID",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.",
	"recommended_actions": "Do not set 'spec.template.spec.hostPID' to true.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failHostPID is true if spec.hostPID is set to true (on all controllers)
failHostPID {
	kubernetes.host_pids[_] == true
}

deny[res] {
	failHostPID

	msg := kubernetes.format(sprintf("%s %s in %s namespace should not set spec.template.spec.hostPID to true", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
