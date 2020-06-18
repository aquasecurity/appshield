package main

import data.lib.kubernetes

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true
failHostPID {
  input.spec.template.spec.hostPID == true
}

deny[msg] {
  failHostPID

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.spec.hostPID to true",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
