package main

import data.lib.kubernetes
import data.lib.utils

default failCapsDropAny = false

# getCapsDropAnyContainers returns names of all containers
# which set securityContext.capabilities.drop
getCapsDropAnyContainers[container] {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.securityContext.capabilities, "drop")
  container := allContainers.name
}

# getNoCapsDropContainers returns names of all containers which
# do not set securityContext.capabilities.drop
getNoCapsDropContainers[container] {
  container := kubernetes.containers[_].name
  not getCapsDropAnyContainers[container]
}

# failCapsDropAny is true if ANY container does not
# set securityContext.capabilities.drop
failCapsDropAny {
  count(getNoCapsDropContainers) > 0
}

deny[msg] {
  failCapsDropAny

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.capabilities.drop",
      [getNoCapsDropContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
