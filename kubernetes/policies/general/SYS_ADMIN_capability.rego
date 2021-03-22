# @title: SYS_ADMIN capability added
# @description: SYS_ADMIN gives the processes running inside the container privileges that are equivalent to root.
# @recommended_actions: Remove the SYS_ADMIN capability from 'containers[].securityContext.capabilities.add'.
# @severity: High
# @id: KSV005
# @links: 

package appshield.KSV005

import data.lib.kubernetes

default failCapsSysAdmin = false

__rego_metadata__ := {
	"id": "KSV005",
	"title": "SYS_ADMIN capability added",
  "version": "v1.0.0",
  "custom": {
  	"severity": "High"
  }
}

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

deny[res] {
  failCapsSysAdmin

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should not include 'SYS_ADMIN' in securityContext.capabilities.add",
      [getCapsSysAdmin[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
  res := {
    "msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "custom":  __rego_metadata__.custom
  }  
}

