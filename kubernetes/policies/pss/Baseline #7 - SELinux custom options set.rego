package appshield.kubernetes.KSV025

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

__rego_metadata__ := {
	"id": "KSV025",
	"title": "SELinux custom options set",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "According to pod security standard 'SElinux', setting custom SELinux options should be disallowed.",
	"recommended_actions": "Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions."
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

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in any container
failSELinuxOpts {
	allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "seLinuxOptions")
}

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in the pod template
failSELinuxOpts {
	allPods := kubernetes.pods[_]
	utils.has_key(allPods.spec.securityContext, "seLinuxOptions")
}

deny[res] {
	failSELinuxOpts

	msg := kubernetes.format(sprintf("%s %s in %s namespace should not set spec.securityContext.seLinuxOptions, spec.containers[*].securityContext.seLinuxOptions or spec.initContainers[*].securityContext.seLinuxOptions.", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
