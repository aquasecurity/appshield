# @title: Limit container CPU
# @description: Enforcing CPU limits prevents DOS via resource exhaustion
# @recommended_actions: Set a limit value under 'containers[].resources.limits.cpu'
# @severity: Low
# @id: KSV011
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

meta_ksv011 = {
  "title": "Limit container CPU",
  "description": "Enforcing CPU limits prevents DOS via resource exhaustion",
  "recommended_actions": "Set a limit value under 'containers[].resources.limits.cpu'",
  "severity": "Low",
  "id": "KSV011",
  "links": ""
}

default failLimitsCPU = false

# getLimitsCPUContainers returns all containers which have set resources.limits.cpu
getLimitsCPUContainers[container] {
  allContainers := kubernetes.containers[_]
  utils.has_key(allContainers.resources.limits, "cpu")
  container := allContainers.name
}

# getNoLimitsCPUContainers returns all containers which have not set
# resources.limits.cpu
getNoLimitsCPUContainers[container] {
  container := kubernetes.containers[_].name
  not getLimitsCPUContainers[container]
}

# failLimitsCPU is true if containers[].resources.limits.cpu is not set
# for ANY container
failLimitsCPU {
  count(getNoLimitsCPUContainers) > 0
}

deny[msg] {
  failLimitsCPU
  msg := json.marshal(meta_ksv011)
}
