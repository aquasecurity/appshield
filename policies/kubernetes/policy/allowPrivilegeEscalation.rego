package main

import data.lib.kubernetes
import data.lib.utils

default checkAllowPrivilegeEscalation = false

# getPrivilegeEscalationContainers returns an array of containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.allowPrivilegeEscalation == true
  container := allContainers
}

getPrivilegeEscalationContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers, "securityContext")
  container := allContainers
}

getPrivilegeEscalationContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers.securityContext, "allowPrivilegeEscalation")
  container := allContainers
}

# checkAllowPrivilegeEscalation is true if any container has
# securityContext.allowPrivilegeEscalation set to true or not set.
checkAllowPrivilegeEscalation {
  count(getPrivilegeEscalationContainers) > 0
}

deny[msg] {
  checkAllowPrivilegeEscalation

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.allowPrivilegeEscalation to false",
      [getPrivilegeEscalationContainers[_].name, lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
