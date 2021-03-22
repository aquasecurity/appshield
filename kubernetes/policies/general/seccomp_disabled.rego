# @title: Seccomp policies disabled
# @description: A program inside the container can bypass Seccomp protection policies.
# @recommended_actions: Remove the 'unconfined' value from 'container.seccomp.security.alpha.kubernetes.io'.
# @severity: Medium
# @id: KSV019
# @links:

package appshield.KSV019

import data.lib.kubernetes

default failSeccompAny = false

__rego_metadata__ := {
	"id": "KSV019",
	"title": "Seccomp policies disabled",
  "version": "v1.0.0",
  "custom": {
  	"severity": "Medium"
  }
}

# getSeccompContainers returns all containers which have a seccomp
# profile set and is profile not set to "unconfined"
getSeccompContainers[container] {
  some i
  keys := [key | key := sprintf("%s/%s", ["container.seccomp.security.alpha.kubernetes.io",
    kubernetes.containers[_].name])]
  seccomp := object.filter(kubernetes.annotations[_], keys)
  val := seccomp[i]
  val != "unconfined"
  [a, c] := split(i, "/")
  container = c
}

# getNoSeccompContainers returns all containers which do not have
# a seccomp profile specified or profile set to "unconfined"
getNoSeccompContainers[container] {
  container := kubernetes.containers[_].name
  not getSeccompContainers[container]
}

# failSeccomp is true if there is ANY container without an seccomp profile
# or has a seccomp profile set to "unconfined"
failSeccomp {
  count(getNoSeccompContainers) > 0
}

deny[res] {
  failSeccomp

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify a seccomp profile",
      [getNoSeccompContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
  res := {
    "msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "custom":  __rego_metadata__.custom
  }    
}
