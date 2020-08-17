# @title: Privileged container
# @description: Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.
# @recommended_actions: Change 'containers[].securityContext.privileged' to 'false'
# @severity: High
# @id: KSV017
# @links: 

package main

import data.lib.kubernetes

meta_ksv017 = {
  "title": "Privileged container",
  "description": "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.",
  "recommended_actions": "Change 'containers[].securityContext.privileged' to 'false'",
  "severity": "High",
  "id": "KSV017",
  "links": ""
}

default failPrivileged = false

# getPrivilegedContainers returns all containers which have
# securityContext.privileged set to true.
getPrivilegedContainers[container] {
  allContainers := kubernetes.containers[_]
  allContainers.securityContext.privileged == true
  container := allContainers.name
}

# failPrivileged is true if there is ANY container with securityContext.privileged
# set to true.
failPrivileged {
  count(getPrivilegedContainers) > 0
}

deny[msg] {
  failPrivileged
  msg := json.marshal(meta_ksv017)
}
