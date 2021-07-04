package appshield.kubernetes.KSV011

import data.lib.kubernetes
import data.lib.utils

default failLimitsCPU = false

__rego_metadata__ := {
	"id": "KSV011",
	"title": "CPU not limited",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "Enforcing CPU limits prevents DoS via resource exhaustion.",
	"recommended_actions": "Set a limit value under 'containers[].resources.limits.cpu'.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.resources.limits, "cpu")
	container := allContainers.name
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers[container] {
	container := kubernetes.containers[_].name
	not getLimitsCPUContainers[container]
}

# failLimitsCPU is true if containers[].resources.limits.cpu is not set
# for ANY container
failLimitsCPU {
	count(getNoLimitsCPUContainers) > 0
}

deny[res] {
	failLimitsCPU

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set resources.limits.cpu", [getNoLimitsCPUContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
