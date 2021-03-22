# @title: hostPath volume mounted with docker.sock
# @description: Mounting docker.sock from the host can give the container full root access to the host.
# @recommended_actions: Do not specify /var/run/docker.socker in 'spec.template.volumes.hostPath.path'.
# @severity: High
# @id: KSV006
# @links: 

package appshield.KSV006

import data.lib.kubernetes

name = input.metadata.name

default checkDockerSocket = false

__rego_metadata__ := {
	"id": "KSV006",
	"title": "hostPath volume mounted with docker.sock",
  "version": "v1.0.0",
  "custom": {
  	"severity": "High"
  }
}
 
# checkDockerSocket is true if volumes.hostPath.path is set to /var/run/docker.sock
# and is false if volumes.hostPath is set to some other path or not set.
checkDockerSocket {
  volumes := kubernetes.volumes
  volumes[_].hostPath.path == "/var/run/docker.sock"
}

deny[res] {
  checkDockerSocket
  # msg = sprintf("%s should not mount /var/run/docker.socker", [name])

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should not specify /var/run/docker.socker in spec.template.volumes.hostPath.path",
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
