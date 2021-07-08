package appshield.kubernetes.KSV025

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

__rego_metadata__ := {
	"id": "KSV025",
	"title": "A custom SELinux user or role option is set",
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

allowed_selinux_types := ["container_t", "container_init_t", "container_kvm_t"]

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in any container
failSELinuxOpts {
	allContainers := kubernetes.containers[_]
	failSecurityContext(allContainers.securityContext.seLinuxOptions)
}

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in the pod template
failSELinuxOpts {
	allPods := kubernetes.pods[_]
	failSecurityContext(allPods.spec.securityContext.seLinuxOptions)
}

failSecurityContext(options) = false {
	not options
}

failSecurityContext(options) {
	not hasAllowedType(options)
}

failSecurityContext(options) {
	utils.has_key(options, "role")
}

failSecurityContext(options) {
	utils.has_key(options, "user")
}

hasAllowedType(options) {
	allowed_selinux_types[_] == options.type
}

hasAllowedType(options) {
	not utils.has_key(options, "type")
}

deny[res] {
	failSELinuxOpts

	msg := kubernetes.format(sprintf("%s '%s' should not set 'spec.securityContext.seLinuxOptions', 'spec.containers[*].securityContext.seLinuxOptions' or 'spec.initContainers[*].securityContext.seLinuxOptions'", [kubernetes.kind, kubernetes.name]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
