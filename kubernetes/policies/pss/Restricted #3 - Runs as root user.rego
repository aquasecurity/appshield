package appshield.kubernetes.KSV012

import data.lib.kubernetes
import data.lib.utils

default checkRunAsNonRoot = false

__rego_metadata__ := {
	"id": "KSV012",
	"title": "Container is running as root user",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Using runAsNonRoot' forces the running image to run as a non-root user to ensure least privileges.",
	"recommended_actions": "Set 'containers[].securityContext.runAsNonRoot' to true.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getNonRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to true.
getNonRootContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.runAsNonRoot == true
	container := allContainers.name
}

# getRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to false or not set.
getRootContainers[container] {
	container := kubernetes.containers[_].name
	not getNonRootContainers[container]
}

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRoot {
	count(getRootContainers) > 0
}

deny[res] {
	checkRunAsNonRoot

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set securityContext.runAsNonRoot to true", [getRootContainers[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
