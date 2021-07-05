package appshield.kubernetes.KSV031

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

__rego_metadata__ := {
	"id": "KSV031",
	"title": "Proc mount not default or undefined",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "The default /proc masks are set up to reduce attack surface, and should be required.",
	"recommended_actions": "Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount, or set to 'Default'"
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

# getContainersWithDefaultProcMount returns the names of all containers which
# set securityContext.procMount to 'Default'
getContainersWithDefaultProcMount[container] {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "procMount")
	allContainers.securityContext.procMount == "Default"
	container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# do not set securityContext
getContainersWithDefaultProcMount[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers, "securityContext")
	container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# do not set securityContext.procMount
getContainersWithDefaultProcMount[container] {
	allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers.securityContext, "procMount")
	container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# set securityContext.procMount to a value other than 'Default'
getContainersWithNonDefaultProcMount[container] {
	container := kubernetes.containers[_].name
	not getContainersWithDefaultProcMount[container]
}

# failProcMount is true if any container sets securityContext.procMount to a value
# other than 'Default'
failProcMount {
	count(getContainersWithNonDefaultProcMount) > 0
}

deny[res] {
	failProcMount

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.procMount to 'Default'", [getContainersWithNonDefaultProcMount[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
