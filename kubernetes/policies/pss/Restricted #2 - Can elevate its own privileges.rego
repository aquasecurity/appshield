package appshield.kubernetes.KSV001

import data.lib.kubernetes
import data.lib.utils

default checkAllowPrivilegeEscalation = false

__rego_metadata__ := {
	"id": "KSV001",
	"title": "Can elevate its own privileges",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "A program inside the container can elevate its own privileges and run as root, which might give the program control over the container and node.",
	"recommended_actions": "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."
}

__rego_input__ := {
  "combine": false,
  "selector": [{
    "type" : "kubernetes", "group": "core", "version": "v1", "kind": "pod"
  },
  {
   "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "replicaset"
  },
  {
    "type" : "kubernetes", "group": "core", "version": "v1", "kind": "replicationcontroller"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "deployment"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "statefulset"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "daemonset"
  },
  {
    "type" : "kubernetes", "group": "batch", "version": "v1", "kind": "cronjob"
  },
  {
    "type" : "kubernetes", "group": "batch", "version": "v1", "kind": "job"
  }]
}

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.allowPrivilegeEscalation == false
	container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
	container := kubernetes.containers[_].name
	not getNoPrivilegeEscalationContainers[container]
}

# checkAllowPrivilegeEscalation is true if any container has
# securityContext.allowPrivilegeEscalation set to true or not set.
checkAllowPrivilegeEscalation {
	count(getPrivilegeEscalationContainers) > 0
}

deny[res] {
	checkAllowPrivilegeEscalation

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.allowPrivilegeEscalation to false", [getPrivilegeEscalationContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
