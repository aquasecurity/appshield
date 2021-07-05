package appshield.kubernetes.KSV004

import data.lib.kubernetes
import data.lib.utils

default failCapsDropAny = false

__rego_metadata__ := {
	"id": "KSV004",
	"title": "Default capabilities: some containers do not drop any",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Security best practices require containers to run with minimal required capabilities.",
	"recommended_actions": "Specify at least one unneeded capability in 'containers[].securityContext.capabilities.drop'",
	"url": "https://kubesec.io/basics/containers-securitycontext-capabilities-drop-index-all/"

}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getCapsDropAnyContainers returns names of all containers
# which set securityContext.capabilities.drop
getCapsDropAnyContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext.capabilities, "drop")
	container := allContainers.name
}

# getNoCapsDropContainers returns names of all containers which
# do not set securityContext.capabilities.drop
getNoCapsDropContainers[container] {
	container := kubernetes.containers[_].name
	not getCapsDropAnyContainers[container]
}

# failCapsDropAny is true if ANY container does not
# set securityContext.capabilities.drop
failCapsDropAny {
	count(getNoCapsDropContainers) > 0
}

deny[res] {
	failCapsDropAny

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.capabilities.drop", [getNoCapsDropContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
