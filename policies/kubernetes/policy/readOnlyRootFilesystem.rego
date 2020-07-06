# @title: Read only file system
# @description: An immutable root filesystem prevents applications from writing to their local disk. This can limit an intrusion as the attacker will not be able to tamper with the filesystem or write foreign executables to disk.
# @recommended_actions: Change 'containers[].securityContext.readOnlyRootFilesystem' to 'true'
# @severity: Low
# @id: KSV014
# @links: 

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
