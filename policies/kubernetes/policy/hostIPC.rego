package main

import data.lib.kubernetes

default failHostIPC = false

# failHostIPC is true if spec.hostIPC is set to true
failHostIPC {
  input.spec.template.spec.hostIPC == true
}

deny[msg] {
  failHostIPC

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.spec.hostIPC to true",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

