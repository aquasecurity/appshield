package main

import data.lib.kubernetes
import data.lib.utils

default checkRunAsNonRoot = false

# getRootContainers returns an array of containers which have
# securityContext.runAsNonRoot set to false or not set.
getRootContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.runAsNonRoot == false
  container := allContainers
}

getRootContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers, "securityContext")
  container := allContainers
}

getRootContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers.securityContext, "runAsNonRoot")
  container := allContainers
}

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRoot {
  count(getRootContainers) > 0
}

deny[msg] {
  checkRunAsNonRoot

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.runAsNonRoot to true",
      [getRootContainers[_].name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
