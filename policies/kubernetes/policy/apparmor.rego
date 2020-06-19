package main

import data.lib.kubernetes

default failAppArmor = false

# getApparmorContainers returns all containers which have an apparmor
# profile set and is profile not set to "unconfined"
getApparmorContainers[container] {
  some i
  keys := [key | key := sprintf("%s/%s", ["container.apparmor.security.beta.kubernetes.io",
    kubernetes.containers[_].name])]
  apparmor := object.filter(kubernetes.annotations, keys)
  val := apparmor[i]
  val != "unconfined"
  [a, c] := split(i, "/")
  container = c
}

# getNoApparmorContainers returns all containers which do not have
# an apparmor profile specified or profile set to "unconfined"
getNoApparmorContainers[container] {
  container := kubernetes.containers[_].name
  not getApparmorContainers[container]
}

# failApparmor is true if there is ANY container without an apparmor profile
# or has an apparmor profile set to "unconfined"
failApparmor {
  count(getNoApparmorContainers) > 0
}

deny[msg] {
  failApparmor

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify an apparmor profile",
      [getNoApparmorContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}

