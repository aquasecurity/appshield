package main

import data.lib.kubernetes

name = input.metadata.name

default checkAllowPrivilegeEscalation = false

checkAllowPrivilegeEscalation {
  containers := kubernetes.containers
  containers[_].securityContext.allowPrivilegeEscalation == true
}

deny[msg] {
  checkAllowPrivilegeEscalation
  msg = sprintf("containers[].securityContext.allowPrivilegeEscalation should be set to 'false' in Deployment '%s'", [name])
}
