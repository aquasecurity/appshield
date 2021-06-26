package appshield.kubernetes.KSV021

import data.lib.kubernetes
import data.lib.utils

default failRunAsGroup = false

__rego_metadata__ := {
	"id": "KSV021",
	"title": "Runs with GID <= 10000",
	"version": "v1.0.0",
	"severity": "Medium",
	"type": "Kubernetes Security Check",
	"description": "Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table.",
	"recommended_actions": "Set 'containers[].securityContext.runAsGroup' to an integer > 10000.",
}

# getGroupIdContainers returns the names of all containers which have
# securityContext.runAsGroup less than or equal to 10000.
getGroupIdContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.runAsGroup <= 10000
	container := allContainers.name
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext.runAsGroup set.
getGroupIdContainers[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers.securityContext, "runAsGroup")
	container := allContainers.name
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext set.
getGroupIdContainers[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers, "securityContext")
	container := allContainers.name
}

# failRunAsGroup is true if securityContext.runAsGroup is less than or
# equal to 10000 or if securityContext.runAsGroup is not set.
failRunAsGroup {
	count(getGroupIdContainers) > 0
}

deny[res] {
	failRunAsGroup

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.runAsGroup > 10000", [getGroupIdContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
