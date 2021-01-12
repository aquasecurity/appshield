# @title: Access to host network
# @description: Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter.
# @recommended_actions: Do not set 'spec.template.spec.hostNetwork' to true.
# @severity: High
# @id: KSV009
# @links: 

package main

import data.lib.kubernetes

default failHostNetwork = false

# failHostNetwork is true if spec.hostNetwork is set to true (on all controllers)
failHostNetwork {
  kubernetes.host_networks[_] == true
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

