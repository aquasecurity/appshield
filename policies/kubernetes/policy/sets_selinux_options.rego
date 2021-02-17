# @title: Setting custom SELinux options should be disallowed.
# @description: Pods should not set SELinux options.
# @recommended_actions: Do not set 'spec.securityContext.seLinuxOptions', spec.containers[*].securityContext.seLinuxOptions and spec.initContainers[*].securityContext.seLinuxOptions.
# @severity:
# @id:
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failSELinux = false

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in any container
failSELinuxOpts {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.securityContext, "seLinuxOptions")
}

# failSELinuxOpts is true if securityContext.seLinuxOptions is set in the pod template
failSELinuxOpts {
  allPods := kubernetes.pods[_]
  utils.has_key(allPods.spec.securityContext, "seLinuxOptions")
}

deny[msg] {
  failSELinuxOpts

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.securityContext.seLinuxOptions, spec.containers[*].securityContext.seLinuxOptions or spec.initContainers[*].securityContext.seLinuxOptions.",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
