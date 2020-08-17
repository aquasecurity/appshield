# @title: Access to host IPC
# @description: Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.
# @recommended_actions: Do not set 'spec.template.spec.hostIPC' to true
# @severity: High
# @id: KSV008
# @links: 

package main

import data.lib.kubernetes

meta_ksv008 = {
  "title": "Access to host IPC",
  "description": "Sharing the host’s IPC namespace allows container processes to communicate with processes on the host.",
  "recommended_actions": "Do not set 'spec.template.spec.hostIPC' to true",
  "severity": "High",
  "id": "KSV008",
  "links": ""
}

default failHostIPC = false

# failHostIPC is true if spec.hostIPC is set to true
failHostIPC {
  input.spec.template.spec.hostIPC == true
}

deny[msg] {
  failHostIPC
  msg := json.marshal(meta_ksv008)
}

