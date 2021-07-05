package appshield.kubernetes.KSV008

import data.lib.kubernetes

default failHostIPC = false

__rego_metadata__ := {
	"id": "KSV008",
	"title": "Access to host IPC namespace",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.",
	"recommended_actions": "Do not set 'spec.template.spec.hostIPC' to true."
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

# failHostIPC is true if spec.hostIPC is set to true (on all resources)
failHostIPC {
	kubernetes.host_ipcs[_] == true
}

deny[res] {
	failHostIPC

	msg := kubernetes.format(sprintf("%s %s in %s namespace should not set spec.template.spec.hostIPC to true", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
