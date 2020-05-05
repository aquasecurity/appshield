package main

import data.lib.kubernetes

name = input.metadata.name

default checkRunAsNonRoot = false

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRoot {
  input.spec.template.spec.containers[_].securityContext.runAsNonRoot == false
}

deny[msg] {
  kubernetes.containers[container]
  checkRunAsNonRoot
  msg = kubernetes.format(sprintf("%s in the %s %s is running as root", [container.name, kubernetes.kind, kubernetes.name]))
}
