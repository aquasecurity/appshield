# @title: Runtime/Default Seccomp profile not set
# @description: According to pod security standard "Seccomp", the RuntimeDefault seccomp profile must be required, or allow specific additional profiles.
# @recommended_actions: Set 'spec.securityContext.seccompProfile.type', 'spec.containers[*].securityContext.seccompProfile' and 'spec.initContainers[*].securityContext.seccompProfile' to RuntimeDefault.
# @severity: Low
# @id: KSV030
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

default failSeccompProfileType = false

# getContainersWithDisallowedSeccompProfileType returns a list of containers
# with seccompProfile type set to anything other than RuntimeDefault
getContainersWithDisallowedSeccompProfileType[name] {
  container := kubernetes.containers[_]
  type := container.securityContext.seccompProfile.type
  not type == "RuntimeDefault"
  name := container.name
}

# failSeccompProfileType is true if pod seccompprofile type is set to any
# value other "RuntimeDefault"
failSeccompProfileType {
  pod := kubernetes.pods[_]
  type := pod.spec.securityContext.seccompProfile.type
  not type == "RuntimeDefault"
}

deny[msg] {
  failSeccompProfileType

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should set spec.securityContext.seccompProfile.type to 'RuntimeDefault'",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

deny[msg] {
  count(getContainersWithDisallowedSeccompProfileType) > 0

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set spec.containers[*].securityContext.seccompProfile.type to 'RuntimeDefault'",
      [getContainersWithDisallowedSeccompProfileType[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
