  
# @title: Access to host PID
# @description: Sharing the host’s PID namespace allows visibility on host processes, potentially leaking information such as environment variables and configuration.
# @recommended_actions: Do not set 'spec.template.spec.hostPID' to true.
# @severity: High
# @id: KSV010
# @links: 

package main

import data.lib.kubernetes

default failHostPID = false

# failHostPID is true if spec.hostPID is set to true
failHostPID {
  input.spec.hostPID == true
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
