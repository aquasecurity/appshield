# @title: Run container as non root user
# @description: Force the running image to run as a non-root user to ensure least privilege
# @recommended_actions: Set 'containers[].securityContext.runAsNonRoot' to true
# @severity: Medium
# @id: KSV012

package main

import data.lib.kubernetes
import data.lib.utils

default checkRunAsNonRoot = false

# getNonRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to true.
getNonRootContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.runAsNonRoot == true
  container := allContainers.name
}

# getRootContainers returns the names of all containers which have
# securityContext.runAsNonRoot set to false or not set.
getRootContainers[container] {
  container := kubernetes.containers[_].name
  not getNonRootContainers[container]
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
      [getRootContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
