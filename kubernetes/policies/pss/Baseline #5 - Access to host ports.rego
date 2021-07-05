package appshield.kubernetes.KSV024

import data.lib.kubernetes

default failHostPorts = false

__rego_metadata__ := {
	"id": "KSV024",
	"title": "Access to host ports",
	"version": "v1.0.0",
	"severity": "HIGH",
	"type": "Kubernetes Security Check",
	"description": "According to pod security standard 'Host Ports', hostPorts should be disallowed, or at minimum restricted to a known list.",
	"recommended_actions": "Do not set spec.containers[*].ports[*].hostPort and spec.initContainers[*].ports[*].hostPort."
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

# Add allowed host ports to this set
allowed_host_ports = set()

# getContainersWithDisallowedHostPorts returns a list of containers which have
# host ports not included in the allowed host port list
getContainersWithDisallowedHostPorts[container] {
	allContainers := kubernetes.containers[_]
	set_host_ports := {port | port := allContainers.ports[_].hostPort}
	host_ports_not_allowed := set_host_ports - allowed_host_ports
	count(host_ports_not_allowed) > 0
	container := allContainers.name
}

# host_ports_msg is a string of allowed host ports to be print as part of deny message
host_ports_msg = "" {
	count(allowed_host_ports) == 0
} else = msg {
	msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_host_ports)])
}

# failHostPorts is true if there are containers which set host ports
# not included in the allowed host ports list
failHostPorts {
	count(getContainersWithDisallowedHostPorts) > 0
}

deny[res] {
	failHostPorts

	msg := sprintf("container %s of %s %s in %s namespace should not set host ports, ports[*].hostPort%s", [getContainersWithDisallowedHostPorts[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, host_ports_msg])

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
