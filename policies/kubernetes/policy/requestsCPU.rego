package main

import data.lib.kubernetes
import data.lib.utils

default failRequestsCPU = false

# getRequestsCPUContainers returns all containers which have set resources.requests.cpu
getRequestsCPUContainers[container] {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.resources.requests, "cpu")
  container := allContainers.name
}

# getNoRequestsCPUContainers returns all containers which have not set
# resources.requests.cpu
getNoRequestsCPUContainers[container] {
  container := kubernetes.containers[_].name
  not getRequestsCPUContainers[container]
}

# failRequestsCPU is true if containers[].resources.requests.cpu is not set
# for ANY container
failRequestsCPU {
  count(getNoRequestsCPUContainers) > 0
}

deny[msg] {
  failRequestsCPU

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set resources.requests.cpu",
      [getNoRequestsCPUContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
