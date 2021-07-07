package appshield.kubernetes.KSV027

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

__rego_metadata__ := {
	"id": "KSV027",
	"title": "The default /proc masks are not used",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "The default /proc masks are set up to reduce attack surface, and should be required.",
	"recommended_actions": "Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "procMount")
}

deny[res] {
	failProcMountOpts

	msg := kubernetes.format(sprintf("%s '%s' should not set spec.containers[*].securityContext.procMount or spec.initContainers[*].securityContext.procMount", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
