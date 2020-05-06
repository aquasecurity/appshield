package main

import data.lib.kubernetes

name = input.metadata.name

hasCapsDropAll {
  input.spec.template.spec.containers[_].securityContext.capabilities.drop[_] == "ALL"
}

default checkCapsDropAll = false

# checkCapsDropAll is true if capabilities drop does not include 'ALL',
# or if capabilities drop is not specified at all.
checkCapsDropAll {
  not hasCapsDropAll
}

deny[msg] {
  kubernetes.is_deployment
  checkCapsDropAll
  msg = sprintf("containers[].securityContext.capabilities.drop should drop 'ALL' capabilities in Deployment '%s'", [name])
}
