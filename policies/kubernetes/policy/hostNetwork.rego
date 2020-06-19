package main

import data.lib.kubernetes

default failHostNetwork = false

# failHostNetwork is true if spec.hostNetwork is set to true
failHostNetwork {
  input.spec.template.spec.hostNetwork == true
}

deny[msg] {
  failHostNetwork

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.spec.hostNetwork to true",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

