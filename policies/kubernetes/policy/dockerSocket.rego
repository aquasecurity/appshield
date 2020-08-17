# @title: Container should not mount the hostpath /var/run/docker.sock 
# @description: Mounting the docker.sock from the host can give the container full root access to the host.
# @recommended_actions: Do not specify /var/run/docker.socker in 'spec.template.volumes.hostPath.path'
# @severity: High
# @id: KSV006
# @links: 

package main

import data.lib.kubernetes

meta_ksv006 = {
  "title": "Container should not mount the hostpath /var/run/docker.sock ",
  "description": "Mounting the docker.sock from the host can give the container full root access to the host.",
  "recommended_actions": "Do not specify /var/run/docker.socker in 'spec.template.volumes.hostPath.path'",
  "severity": "High",
  "id": "KSV006",
  "links": ""
}

name = input.metadata.name

default checkDockerSocket = false
 
# checkDockerSocket is true if volumes.hostPath.path is set to /var/run/docker.sock
# and is false if volumes.hostPath is set to some other path or not set.
checkDockerSocket {
  volumes := kubernetes.volumes
  volumes[_].hostPath.path == "/var/run/docker.sock"
}

deny[msg] {
  checkDockerSocket
  msg := json.marshal(meta_ksv006)
}
