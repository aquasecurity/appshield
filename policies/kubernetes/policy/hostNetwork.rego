# @title: Access to host network
# @description: Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter
# @recommended_actions: Do not set 'spec.template.spec.hostNetwork' to true
# @severity: High
# @id: KSV009
# @links: 

package main

import data.lib.kubernetes

meta_ksv009 = {
  "title": "Access to host network",
  "description": "Sharing the host’s network namespace permits processes in the pod to communicate with processes bound to the host’s loopback adapter",
  "recommended_actions": "Do not set 'spec.template.spec.hostNetwork' to true",
  "severity": "High",
  "id": "KSV009",
  "links": ""
}

default failHostNetwork = false

# failHostNetwork is true if spec.hostNetwork is set to true
failHostNetwork {
  input.spec.template.spec.hostNetwork == true
}

deny[msg] {
  failHostNetwork
  msg := json.marshal(meta_ksv009)
}

