package main

import data.lib.kubernetes

default checkCapsDropAll = false

# Get all containers which include 'ALL' in security.capabilities.drop
getCapsDropAllContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.capabilities.drop[_] == "ALL"
  container := allContainers.name
}

# Get all containers which don't include 'ALL' in security.capabilities.drop
getCapsNoDropAllContainers[container] {
  container := kubernetes.containers[_].name
  not getCapsDropAllContainers[container]
}

# checkCapsDropAll is true if capabilities drop does not include 'ALL',
# or if capabilities drop is not specified at all.
checkCapsDropAll {
  count(getCapsNoDropAllContainers) > 0
}

deny[msg] {
  checkCapsDropAll

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should add 'ALL' to securityContext.capabilities.drop",
      [getCapsNoDropAllContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
