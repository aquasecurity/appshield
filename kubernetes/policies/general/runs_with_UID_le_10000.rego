package appshield.kubernetes.KSV020

import data.lib.kubernetes
import data.lib.utils

default failRunAsUser = false

__rego_metadata__ := {
	"id": "KSV020",
	"title": "Runs with UID <= 10000",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Force the container to run with user ID > 10000 to avoid conflicts with the host’s user table.",
	"recommended_actions": "Set 'containers[].securityContext.runAsUser' to an integer > 10000."
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

# getUserIdContainers returns the names of all containers which have
# securityContext.runAsUser less than or equal to 100000.
getUserIdContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.runAsUser <= 10000
	container := allContainers.name
}

# getUserIdContainers returns the names of all containers which do
# not have securityContext.runAsUser set.
getUserIdContainers[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers.securityContext, "runAsUser")
	container := allContainers.name
}

# getUserIdContainers returns the names of all containers which do
# not have securityContext set.
getUserIdContainers[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers, "securityContext")
	container := allContainers.name
}

# failRunAsUser is true if securityContext.runAsUser is less than or
# equal to 10000 or if securityContext.runAsUser is not set.
failRunAsUser {
	count(getUserIdContainers) > 0
}

deny[res] {
	failRunAsUser

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.runAsUser > 10000", [getUserIdContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
