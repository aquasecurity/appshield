# @title: Access to host IPC
# @description: Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.
# @recommended_actions: Do not set 'spec.template.spec.hostIPC' to true
# @severity: High

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

