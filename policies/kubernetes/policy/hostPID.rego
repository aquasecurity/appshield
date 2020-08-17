# @title: Access to host PID
# @description: Sharing the host’s PID namespace allows visibility of processes on the host, potentially leaking information such as environment variables and configuration
# @recommended_actions: Do not set 'spec.template.spec.hostPID' to true
# @severity: High
# @id: KSV010
# @links: 

package main

import data.lib.kubernetes

meta_ksv010 = {
  "title": "Access to host PID",
  "description": "Sharing the host’s PID namespace allows visibility of processes on the host, potentially leaking information such as environment variables and configuration",
  "recommended_actions": "Do not set 'spec.template.spec.hostPID' to true",
  "severity": "High",
  "id": "KSV010",
  "links": ""
}

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true
failHostPID {
  input.spec.template.spec.hostPID == true
}

deny[msg] {
  failHostPID
  msg := json.marshal(meta_ksv010)
}
