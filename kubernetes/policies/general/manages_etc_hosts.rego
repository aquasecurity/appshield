package appshield.kubernetes.KSV007

import data.lib.kubernetes
import data.lib.utils

default failHostAliases = false

__rego_metadata__ := {
    "id": "KSV007",
    "title": "Manages /etc/hosts",
    "version": "v1.0.0",
    "severity": "Low",
    "type": "Kubernetes Security Check",
    "description": "Managing /etc/hosts aliases can prevent the container engine from modifying the file after a pod’s containers have already been started.",
    "recommended_actions": "Do not set 'spec.template.spec.hostAliases'.",
}

# failHostAliases is true if spec.hostAliases is set (on all controllers)
failHostAliases {
  utils.has_key(kubernetes.host_aliases[_], "hostAliases")
}

deny[res] {
  failHostAliases

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.spec.hostAliases",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
    res := {
    	"msg": msg,
        "id":  __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type":  __rego_metadata__.type,
    }
}

