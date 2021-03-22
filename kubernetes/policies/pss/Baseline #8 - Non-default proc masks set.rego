# @title: Non-default /proc masks set
# @description: According to pod security standard "/proc Mount Type”, the default /proc masks are set up to reduce attack surface, and should be required.
# @recommended_actions: Do not set spec.containers[*].securityContext.procMount and spec.initContainers[*].securityContext.procMount.
# @severity: Medium
# @id: KSV027
# @links:

package appshield.KSV027

import data.lib.kubernetes
import data.lib.utils

default failProcMount = false

__rego_metadata__ := {
	"id": "KSV027",
	"title": "Non-default /proc masks set",
    "version": "v1.0.0",
    "custom": {
  	    "severity": "Medium"
  }
}

# failProcMountOpts is true if securityContext.procMount is set in any container
failProcMountOpts {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.securityContext, "procMount")
}

deny[res] {
  failProcMountOpts

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not set spec.containers[*].securityContext.procMount or spec.initContainers[*].securityContext.procMount.",
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
    res := {
      "msg": msg,
      "id":  __rego_metadata__.id,
      "title": __rego_metadata__.title,
      "custom":  __rego_metadata__.custom
    }
}
