# @title: Non-default /proc masks set
# @description: According to pod security standard "/proc Mount Type”, the default /proc masks are set up to reduce attack surface, and should be required.
# @recommended_actions: Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount.
# @severity: Medium
# @id: KSV027
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.securityContext, "procMount")
}

deny[msg] {
  failProcMountOpts

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.containers[*].securityContext.procMount or spec.initContainers[*].securityContext.procMount.",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
