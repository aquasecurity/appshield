package appshield.kubernetes.KSV005

import data.lib.kubernetes

default failCapsSysAdmin = false

__rego_metadata__ := {
	"id": "KSV005",
	"title": "SYS_ADMIN capability added",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
	"recommended_actions": "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'."
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

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysAdmin[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.capabilities.add[_] == "SYS_ADMIN"
	container := allContainers.name
}

# failCapsSysAdmin is true if securityContext.capabilities.add
# includes 'SYS_ADMIN'.
failCapsSysAdmin {
	count(getCapsSysAdmin) > 0
}

deny[res] {
	failCapsSysAdmin

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should not include 'SYS_ADMIN' in securityContext.capabilities.add", [getCapsSysAdmin[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
