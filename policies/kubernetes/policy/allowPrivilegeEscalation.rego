# @title: Workload is allowed to elevate privileges
# @description: A program inside the container can elevate its privileges and run as root, which might give the program control over the container and node.
# @recommended_actions: Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'
# @severity: Medium

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
