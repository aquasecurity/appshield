package main

import data.lib.kubernetes

name = input.metadata.name

default checkRunAsNonRoot = false

# checkRunAsNonRoot is true if securityContext.runAsNonRoot is set to false
# or if securityContext.runAsNonRoot is not set.
checkRunAsNonRoot {
  containers := kubernetes.containers
  containers[_].securityContext.runAsNonRoot == false
}

deny[msg] {
  checkRunAsNonRoot

  some i
  containers := kubernetes.containers
  containers[i].securityContext.runAsNonRoot == false
  msg = kubernetes.format(sprintf("%s in the %s %s is running as root", [containers[i].name, kubernetes.kind, kubernetes.name]))
}
