package main

import data.lib.kubernetes

__rego__metadoc__ := {
  "id": "KSV017",
  "title": "Privileged",
  "description": "Privileged containers share namespaces with the host system and do not offer any security. They should be used exclusively for system containers that require high privileges.",
  "custom": {
      "Recommendation": "Change 'containers[].securityContext.privileged' to 'false'",
      "Severity": "High"
  },
  "entrypoint": "main.deny",
  "input": "Kubernetes Pod spec OR a Kubernetes admission review object with for a Pod spec",
  "output": "Set of messages pertaining to affected items",
  "examples": [
    "main.test_Privileged_is_true",
    "main.test_Privileged_is_false"
  ]
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

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should set securityContext.privileged to false",
      [getPrivilegedContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
