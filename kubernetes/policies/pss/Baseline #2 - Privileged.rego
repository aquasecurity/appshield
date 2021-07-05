package appshield.kubernetes.KSV017

import data.lib.kubernetes

default failPrivileged = false

__rego_metadata__ := {
	"id": "KSV017",
	"title": "Privileged",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.",
	"recommended_actions": "Change 'containers[].securityContext.privileged' to 'false'."
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

# getPrivilegedContainers returns all containers which have
# securityContext.privileged set to true.
getPrivilegedContainers[container] {
	allContainers := kubernetes.containers[_]
	allContainers.securityContext.privileged == true
	container := allContainers.name
}

# failPrivileged is true if there is ANY container with securityContext.privileged
# set to true.
failPrivileged {
	count(getPrivilegedContainers) > 0
}

deny[res] {
	failPrivileged

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should set securityContext.privileged to false", [getPrivilegedContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
