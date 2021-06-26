package appshield.kubernetes.KSV009

import data.lib.kubernetes

default failHostNetwork = false

__rego_metadata__ := {
	"id": "KSV009",
	"title": "Access to host network",
	"version": "v1.0.0",
	"severity": "High",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.",
	"recommended_actions": "Do not set 'spec.template.spec.hostNetwork' to true.",
}

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork {
	kubernetes.host_networks[_] == true
}

deny[res] {
	failHostNetwork

	msg := kubernetes.format(sprintf("%s %s in %s namespace should not set spec.template.spec.hostNetwork to true", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
