package main

import data.lib.kubernetes

name = input.metadata.name

runAsNonRoot {
  input.spec.template.spec.containers[_].securityContext.runAsNonRoot == true
}

deny[msg] {
  kubernetes.containers[container]
	not runAsNonRoot
	msg = kubernetes.format(sprintf("%s in the %s %s is running as root", [container.name, kubernetes.kind, kubernetes.name]))
}