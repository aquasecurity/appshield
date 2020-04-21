package main

import data.lib.kubernetes


name = input.metadata.name

dropAll {
  input.spec.template.spec.containers[_].securityContext.capabilities.drop[_] == "ALL"
}

deny[msg] {
  kubernetes.is_deployment
  not dropAll
  msg = sprintf("containers[].securityContext.capabilities.drop should drop 'ALL' capabilities in Deployment '%s'", [name])
}