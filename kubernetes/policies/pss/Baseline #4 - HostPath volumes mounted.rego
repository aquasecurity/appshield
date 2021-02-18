# @title: HostPath volumes mounted
# @description: According to pod security standard "HostPath Volumes", HostPath volumes must be forbidden.
# @recommended_actions: Do not set 'spec.volumes[*].hostPath'.
# @severity: Medium
# @id: KSV023
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume = false

failHostPathVolume {
  volumes := kubernetes.volumes
  utils.has_key(volumes[_], "hostPath")
}

deny[msg] {
  failHostPathVolume

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.volumes.hostPath",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
