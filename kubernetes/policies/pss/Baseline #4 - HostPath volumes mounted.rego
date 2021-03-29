package appshield.kubernetes.KSV023

import data.lib.kubernetes
import data.lib.utils

default failHostPathVolume = false

__rego_metadata__ := {
     "id": "KSV023",
     "title": "HostPath volumes mounted",
     "version": "v1.0.0",
     "severity": "Medium",
     "type": "Kubernetes Security Check",
     "description": "According to pod security standard 'HostPath Volumes', HostPath volumes must be forbidden.",
     "recommended_actions": "Do not set 'spec.volumes[*].hostPath'.",
}

failHostPathVolume {
  volumes := kubernetes.volumes
  utils.has_key(volumes[_], "hostPath")
}

deny[res] {
  failHostPathVolume

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.template.volumes.hostPath",
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
