# @title: Default capabilities: some containers do not drop any
# @description: Security best practices require containers to run with minimal required capabilities.
# @recommended_actions: Specify at least one unneeded capability in 'containers[].securityContext.capabilities.drop'.
# @severity: Low
# @id: KSV004
# @links: 

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
