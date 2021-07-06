package appshield.kubernetes.KSV025

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

__rego_metadata__ := {
	"id": "KSV025",
	"title": "A custom SELinux user or role option should not be set",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Setting a custom SELinux user or role option should be forbidden.",
	"recommended_actions": "Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in any container
failSELinuxOpts {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "seLinuxOptions")
}

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in the pod template
failSELinuxOpts {
	allPods := kubernetes.pods[_]
	utils.has_key(allPods.spec.securityContext, "seLinuxOptions")
}

deny[res] {
	failSELinuxOpts

	msg := kubernetes.format(sprintf("%s '%s' should not set spec.securityContext.seLinuxOptions, spec.containers[*].securityContext.seLinuxOptions or spec.initContainers[*].securityContext.seLinuxOptions", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
