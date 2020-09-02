# @title: Manages /etc/hosts 
# @description: Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started.
# @recommended_actions: Do not set 'spec.template.spec.hostAliases'.
# @severity: Low
# @id: KSV007
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

default failHostAliases = false

# failHostAliases is true if spec.hostAliases is set
failHostAliases {
  utils.has_key(input.spec, "hostAliases")
}

deny[msg] {
  failHostAliases

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.spec.hostAliases",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

