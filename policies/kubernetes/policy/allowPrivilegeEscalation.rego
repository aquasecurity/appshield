package main

import data.lib.kubernetes
import data.lib.utils

default checkAllowPrivilegeEscalation = false

# getNoPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to false.
getNoPrivilegeEscalationContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.allowPrivilegeEscalation == false
  container := allContainers.name
}

# getPrivilegeEscalationContainers returns the names of all containers which have
# securityContext.allowPrivilegeEscalation set to true or not set.
getPrivilegeEscalationContainers[container] {
  container := kubernetes.containers[_].name
  not getNoPrivilegeEscalationContainers[container]
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
      [getPrivilegeEscalationContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
