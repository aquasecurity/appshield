# @title: HostPath volumes must be forbidden
# @description: Pods should not use hostpath volumes.
# @recommended_actions: Do not set 'spec.volumes[*].hostPath'.
# @severity:
# @id:
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume = false

# failHostPathVolume is true if the workload has a hostPath volume
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
