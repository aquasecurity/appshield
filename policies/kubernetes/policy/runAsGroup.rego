# @title: Run as Group ID > 10000
# @description: Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table
# @recommended_actions: Set 'containers[].securityContext.runAsGroup' to integer > 10000
# @severity: Medium
# @id: KSV021
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

meta_ksv021 = {
  "title": "Run as Group ID > 10000",
  "description": "Force the container to run with group ID > 10000 to avoid conflicts with the host’s user table",
  "recommended_actions": "Set 'containers[].securityContext.runAsGroup' to integer > 10000",
  "severity": "Medium",
  "id": "KSV021",
  "links": ""
}

default failRunAsGroup = false

# getGroupIdContainers returns the names of all containers which have
# securityContext.runAsGroup less than or equal to 10000.
getGroupIdContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.runAsGroup <= 10000
  container := allContainers.name
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext.runAsGroup set.
getGroupIdContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers.securityContext, "runAsGroup")
  container := allContainers.name
}

# getGroupIdContainers returns the names of all containers which do
# not have securityContext set.
getGroupIdContainers[container] {
  allContainers := kubernetes.containers[_]
  not utils.has_key(allContainers, "securityContext")
  container := allContainers.name
}

# failRunAsGroup is true if securityContext.runAsGroup is less than or
# equal to 10000 or if securityContext.runAsGroup is not set.
failRunAsGroup {
  count(getGroupIdContainers) > 0
}

deny[msg] {
  failRunAsGroup
  msg := json.marshal(meta_ksv021)
}
