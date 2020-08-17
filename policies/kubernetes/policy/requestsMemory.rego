# @title: Memory Requests
# @description: When containers have resource requests specified the scheduler can make better decisions about which nodes to place Pods on and how to deal with resource contention
# @recommended_actions: Set 'containers[].resources.requests.memory' 
# @severity: Low
# @id: KSV016
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

meta_ksv016 = {
  "title": "Memory Requests",
  "description": "When containers have resource requests specified the scheduler can make better decisions about which nodes to place Pods on and how to deal with resource contention",
  "recommended_actions": "Set 'containers[].resources.requests.memory' ",
  "severity": "Low",
  "id": "KSV016",
  "links": ""
}

default failRequestsMemory = false

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

deny[msg] {
  failRequestsMemory
  msg := json.marshal(meta_ksv016)
}
