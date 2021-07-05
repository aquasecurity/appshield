package appshield.kubernetes.KSV012

import data.lib.kubernetes
import data.lib.utils

default checkRunAsNonRoot = false

__rego_metadata__ := {
	"id": "KSV012",
	"title": "Runs as root user",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "Force the running image to run as a non-root user to ensure least privileges.",
	"recommended_actions": "Set 'containers[].securityContext.runAsNonRoot' to true."
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

# getNonRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to true.
getNonRootContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.runAsNonRoot == true
	container := allContainers.name
}

# getRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to false or not set.
getRootContainers[container] {
	container := kubernetes.containers[_].name
	not getNonRootContainers[container]
}

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRoot {
	count(getRootContainers) > 0
}

deny[res] {
	checkRunAsNonRoot

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.runAsNonRoot to true", [getRootContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
