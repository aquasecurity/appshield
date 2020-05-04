package main

import data.lib.kubernetes

name = input.metadata.name

default checkAllowPrivilegeEscalation = false

checkAllowPrivilegeEscalation {
  input.spec.template.spec.containers[_].securityContext.allowPrivilegeEscalation == true
}

deny[msg] {
  kubernetes.containers[container]
  checkAllowPrivilegeEscalation
  msg = sprintf("containers[].securityContext.allowPrivilegeEscalation should be set to 'false' in Deployment '%s'", [name])
}
