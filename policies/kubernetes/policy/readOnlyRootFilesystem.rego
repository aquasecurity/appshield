package main

import data.lib.kubernetes

default failReadOnlyRootFilesystem = false

# getReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyFilesystem set to true.
getReadOnlyRootFilesystemContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.readOnlyRootFilesystem == true
  container := allContainers.name
}

# getNotReadOnlyRootFilesystemContainers returns all containers that have
# securityContext.readOnlyRootFilesystem set to false or not set at all.
getNotReadOnlyRootFilesystemContainers[container] {
  container := kubernetes.containers[_].name
  not getReadOnlyRootFilesystemContainers[container]
}

# failReadOnlyRootFilesystem is true if ANY container sets
# securityContext.readOnlyRootFilesystem set to false or not set at all.
failReadOnlyRootFilesystem {
  count(getNotReadOnlyRootFilesystemContainers) > 0
}

deny[msg] {
  failReadOnlyRootFilesystem

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.readOnlyRootFilesystem to true",
      [getNotReadOnlyRootFilesystemContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
