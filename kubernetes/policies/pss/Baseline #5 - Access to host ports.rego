# @title: Access to host ports
# @description: According to pod security standard "Host Ports", hostPorts should be disallowed, or at minimum restricted to a known list.
# @recommended_actions: Do not set spec.containers[*].ports[*].hostPort and spec.initContainers[*].ports[*].hostPort.
# @severity: High
# @id: KSV024
# @links: 

package appshield.KSV024

import data.lib.kubernetes

default failHostPorts = false

__rego_metadata__ := {
	"id": "KSV024",
	"title": "Access to host ports",
    "version": "v1.0.0",
    "custom": {
  	    "severity": "High"
  }
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

  msg := sprintf("container %s of %s %s in %s namespace should not set host ports, ports[*].hostPort%s", 
    [getContainersWithDisallowedHostPorts[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, host_ports_msg])
    res := {
      "msg": msg,
      "id":  __rego_metadata__.id,
      "title": __rego_metadata__.title,
      "custom":  __rego_metadata__.custom
    }
}
