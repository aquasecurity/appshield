# @title: Proc mount not default or undefined
# @description: The default /proc masks are set up to reduce attack surface, and should be required.
# @recommended_actions: Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount, or set to 'Default'
# @severity:
# @id:
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

# getContainersWithDefaultProcMount returns the names of all containers which
# set securityContext.procMount to 'Default'
getContainersWithDefaultProcMount[container] {
    allContainers := kubernetes.containers[_]
	utils.has_key(allContainers.securityContext, "procMount")
    allContainers.securityContext.procMount == "Default"
    container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# do not set securityContext
getContainersWithDefaultProcMount[container] {
    allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers, "securityContext")
    container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# do not set securityContext.procMount
getContainersWithDefaultProcMount[container] {
    allContainers := kubernetes.containers[_]
	not utils.has_key(allContainers.securityContext, "procMount")
    container := allContainers.name
}

# getContainersWithDefaultProcMount returns the names of all containers which
# set securityContext.procMount to a value other than 'Default'
getContainersWithNonDefaultProcMount[container] {
	container := kubernetes.containers[_].name
    not getContainersWithDefaultProcMount[container]
}

# failProcMount is true if any container sets securityContext.procMount to a value
# other than 'Default'
failProcMount {
  count(getContainersWithNonDefaultProcMount) > 0
}

deny[msg] {
  failProcMount

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.procMount to 'Default'",
      [getContainersWithNonDefaultProcMount[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
