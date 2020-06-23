package main

import data.lib.kubernetes
import data.lib.utils

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

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set resources.requests.memory",
      [getNoRequestsMemoryContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
