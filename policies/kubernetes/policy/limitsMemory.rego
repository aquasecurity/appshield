package main

import data.lib.kubernetes
import data.lib.utils

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

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set resources.limits.memory",
      [getNoLimitsMemoryContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
