# @title: Runs with a root primary or supplementary GID
# @description: According to pod security standard "Non-root groups", containers should be forbidden from running with a root primary or supplementary GID.
# @recommended_actions: Set 'containers[].securityContext.runAsGroup' to a non-zero integer or leave undefined.
# @severity: Low
# @id: KSV029
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

default failRootGroupId = false

# getContainersWithRootGroupId returns a list of containers
# with root group id set
getContainersWithRootGroupId[name] {
  container := kubernetes.containers[_]
  container.securityContext.runAsGroup == 0
  name := container.name
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
  pod := kubernetes.pods[_]
  pod.spec.securityContext.runAsGroup == 0
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
  pod := kubernetes.pods[_]
  gid := pod.spec.securityContext.supplementalGroups[_]
  gid == 0
}

# failRootGroupId is true if root group id is set on pod
failRootGroupId {
  pod := kubernetes.pods[_]
  pod.spec.securityContext.fsGroup == 0
}

deny[msg] {
  failRootGroupId

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should set spec.securityContext.runAsGroup, spec.securityContext.supplementalGroups[*] and spec.securityContext.fsGroup to integer greater than 0",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

deny[msg] {
  count(getContainersWithRootGroupId) > 0

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set spec.securityContext.runAsGroup to integer greater than  0",
      [getContainersWithRootGroupId[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
