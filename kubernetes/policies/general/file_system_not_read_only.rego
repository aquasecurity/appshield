package appshield.KSV014

import data.lib.kubernetes

default failReadOnlyRootFilesystem = false

__rego_metadata__ := {
	"id": "KSV014",
	"title": "Root file system is not read-only",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "An immutable root file system prevents applications from writing to their local disk. This can limit intrusions, as attackers will not be able to tamper with the file system or write foreign executables to disk.",
	"recommended_actions": "Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'.",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

# getReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyFilesystem set to true.
getReadOnlyRootFilesystemContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.readOnlyRootFilesystem == true
	container := allContainers.name
}

# getNotReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyRootFilesystem set to false or not set at all.
getNotReadOnlyRootFilesystemContainers[container] {
	container := kubernetes.containers[_].name
	not getReadOnlyRootFilesystemContainers[container]
}

# failReadOnlyRootFilesystem is true if ANY container sets
# securityContext.readOnlyRootFilesystem set to false or not set at all.
failReadOnlyRootFilesystem {
	count(getNotReadOnlyRootFilesystemContainers) > 0
}

deny[res] {
	failReadOnlyRootFilesystem

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.readOnlyRootFilesystem to true", [getNotReadOnlyRootFilesystemContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
