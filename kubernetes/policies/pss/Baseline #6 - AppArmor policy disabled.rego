package appshield.kubernetes.KSV002

import data.lib.kubernetes

default failAppArmor = false

__rego_metadata__ := {
     "id": "KSV002",
     "title": "AppArmor policies disabled",
     "version": "v1.0.0",
     "severity": "Medium",
     "type": "Kubernetes Security Check",
     "description": "A program inside the container can bypass AppArmor protection policies.",
     "recommended_actions": "Remove the 'unconfined' value from 'container.apparmor.security.beta.kubernetes.io'.",
}

# getApparmorContainers returns all containers which have an AppArmor
# profile set and is profile not set to "unconfined"
getApparmorContainers[container] {
  some i
  keys := [key | key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io",
    kubernetes.containers[_].name])]
  apparmor := object.filter(kubernetes.annotations[_], keys)
  val := apparmor[i]
  val != "unconfined"
  [a, c] := split(i, "/")
  container = c
}

# getNoApparmorContainers returns all containers which do not have
# an AppArmor profile specified or profile set to "unconfined"
getNoApparmorContainers[container] {
  container := kubernetes.containers[_].name
  not getApparmorContainers[container]
}

# failApparmor is true if there is ANY container without an AppArmor profile
# or has an AppArmor profile set to "unconfined"
failApparmor {
  count(getNoApparmorContainers) > 0
}

deny[res] {
  failApparmor

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify an AppArmor profile",
      [getNoApparmorContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
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

