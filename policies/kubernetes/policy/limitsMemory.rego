# @title: Limit container memory
# @description: Enforcing memory limits prevents DOS via resource exhaustion
# @recommended_actions: Set a limit value under 'containers[].resources.limits.memory'
# @severity: Low
# @id: KSV018
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

meta_ksv018 = {
  "title": "Limit container memory",
  "description": "Enforcing memory limits prevents DOS via resource exhaustion",
  "recommended_actions": "Set a limit value under 'containers[].resources.limits.memory'",
  "severity": "Low",
  "id": "KSV018",
  "links": ""
}

default failLimitsMemory = false

# getLimitsMemoryContainers returns all containers which have set resources.limits.memory
getLimitsMemoryContainers[container] {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.resources.limits, "memory")
  container := allContainers.name
}

# getNoLimitsMemoryContainers returns all containers which have not set
# resources.limits.memory
getNoLimitsMemoryContainers[container] {
  container := kubernetes.containers[_].name
  not getLimitsMemoryContainers[container]
}

# failLimitsMemory is true if containers[].resources.limits.memory is not set
# for ANY container
failLimitsMemory {
  count(getNoLimitsMemoryContainers) > 0
}

deny[msg] {
  failLimitsMemory
  msg := json.marshal(meta_ksv018)
}
