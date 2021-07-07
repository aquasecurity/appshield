package appshield.kubernetes.KSV030

import data.lib.kubernetes
import data.lib.utils

default failSeccompProfileType = false

__rego_metadata__ := {
	"id": "KSV030",
	"title": "The default seccomp profile is not used",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "The RuntimeDefault seccomp profile must be required, or allow specific additional profiles.",
	"recommended_actions": "Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to 'runtime/default' or undefined.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getContainersWithDisallowedSeccompProfileType returns a list of containers
# with seccompProfile type set to anything other than RuntimeDefault
getContainersWithDisallowedSeccompProfileType[name] {
	container := kubernetes.containers[_]
	type := container.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
	name := container.name
}

# failSeccompProfileType is true if pod seccompprofile type is set to any
# value other "RuntimeDefault"
failSeccompProfileType {
	pod := kubernetes.pods[_]
	type := pod.spec.securityContext.seccompProfile.type
	not type == "RuntimeDefault"
}

deny[res] {
	failSeccompProfileType

	msg := kubernetes.format(sprintf("%s '%s' should set spec.securityContext.seccompProfile.type to 'RuntimeDefault'", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

deny[res] {
	count(getContainersWithDisallowedSeccompProfileType) > 0

	msg := kubernetes.format(sprintf("Container '%s' of %s '%s' should set spec.containers[*].securityContext.seccompProfile.type to 'RuntimeDefault'", [getContainersWithDisallowedSeccompProfileType[_], kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
