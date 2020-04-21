package main

import data.lib.kubernetes


name = input.metadata.name

allowPrivilegeEscalation {
  input.spec.template.spec.containers[_].securityContext.allowPrivilegeEscalation == false
}

deny[msg] {
  kubernetes.containers[container]
  not allowPrivilegeEscalation
  msg = sprintf("containers[].securityContext.allowPrivilegeEscalation should be set to 'false' in Deployment '%s'", [name])
}