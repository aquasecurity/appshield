package main

import data.lib.kubernetes

name = input.metadata.name

hasCapsDropAll {
  containers := kubernetes.containers
  containers[_].securityContext.capabilities.drop[_] == "ALL"
}

default checkCapsDropAll = false

# checkCapsDropAll is true if capabilities drop does not include 'ALL',
# or if capabilities drop is not specified at all.
checkCapsDropAll {
  not hasCapsDropAll
}

deny[msg] {
  checkCapsDropAll
  msg = sprintf("containers[].securityContext.capabilities.drop should drop 'ALL' capabilities in Deployment '%s'", [name])
}
