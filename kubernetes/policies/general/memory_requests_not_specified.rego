# @title: Memory requests not specified
# @description: When containers have memory requests specified, the scheduler can make better decisions about which nodes to place pods on, and how to deal with resource contention.
# @recommended_actions: Set 'containers[].resources.requests.memory'.
# @severity: Low
# @id: KSV016
# @links: 

package appshield.KSV016

import data.lib.kubernetes
import data.lib.utils

default failRequestsMemory = false

__rego_metadata__ := {
	"id": "KSV016",
	"title": "Memory requests not specified",
  "version": "v1.0.0",
  "custom": {
  	"severity": "Low"
  }
}

# getRequestsMemoryContainers returns all containers which have set resources.requests.memory
getRequestsMemoryContainers[container] {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.resources.requests, "memory")
  container := allContainers.name
}

# getNoRequestsMemoryContainers returns all containers which have not set
# resources.requests.memory
getNoRequestsMemoryContainers[container] {
  container := kubernetes.containers[_].name
  not getRequestsMemoryContainers[container]
}

# failRequestsMemory is true if containers[].resources.requests.memory is not set
# for ANY container
failRequestsMemory {
  count(getNoRequestsMemoryContainers) > 0
}

deny[res] {
  failRequestsMemory

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set resources.requests.memory",
      [getNoRequestsMemoryContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
  res := {
    "msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "custom":  __rego_metadata__.custom
  }   
}
