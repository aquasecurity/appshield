# @title: Container should not include SYS_ADMIN capability
# @description: SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.
# @recommended_actions: Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'
# @severity: High
# @id: KSV005
# @links: 

package main

import data.lib.kubernetes

meta_ksv005 = {
  "title": "Container should not include SYS_ADMIN capability",
  "description": "SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.",
  "recommended_actions": "Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'",
  "severity": "High",
  "id": "KSV005",
  "links": ""
}

default failCapsSysAdmin = false

# getCapsSysAdmin returns the names of all containers which include
# 'SYS_ADMIN' in securityContext.capabilities.add.
getCapsSysAdmin[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.capabilities.add[_] == "SYS_ADMIN"
  container := allContainers.name
}

# failCapsSysAdmin is true if securityContext.capabilities.add
# includes 'SYS_ADMIN'.
failCapsSysAdmin {
  count(getCapsSysAdmin) > 0
}

deny[msg] {
  failCapsSysAdmin
  msg := json.marshal(meta_ksv005)
}

