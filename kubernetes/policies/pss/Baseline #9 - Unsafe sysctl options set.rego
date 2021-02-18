# @title: Unsafe sysctl options set
# @description: Sysctls can disable security mechanisms or affect all containers on a host, and should be disallowed except for an allowed "safe" subset. A sysctl is considered safe if it is namespaced in the container or the pod, and is isolated from other pods and processes on the same node.
# @recommended_actions: Do not set 'spec.securityContext.sysctls' or set to values in allowed subset.
# @severity: Medium
# @id: KSV026
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failSysctls = false

# Add allowed sysctls
allowed_sysctls = {
  "kernel.shm_rmid_forced",
  "net.ipv4.ip_local_port_range",
  "net.ipv4.tcp_syncookies",
  "net.ipv4.ping_group_range"
}

# failSysctls is true if a disallowed sysctl is set
failSysctls {
  pod := kubernetes.pods[_]
  set_sysctls := {sysctl | sysctl := pod.spec.securityContext.sysctls[_].name}
  sysctls_not_allowed := set_sysctls - allowed_sysctls
  count(sysctls_not_allowed) > 0
}

# sysctl_msg is a string of allowed sysctls to be print as part of deny message
sysctl_msg = msg {
  msg := sprintf(" or set it to the following allowed values: %s", [concat(", ", allowed_sysctls)])
}

deny[msg] {
  failSysctls

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set securityContext.sysctl%s",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, sysctl_msg]
    )
  )
}
