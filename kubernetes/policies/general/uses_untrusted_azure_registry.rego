# @title: Container images from non-ACR registries used
# @description: Containers should only use images from trusted Azure registries.
# @recommended_actions: Use images from trusted Azure registries.
# @severity: Medium
# @id: KSV032
# @links:

package appshield.KSV032

import data.lib.kubernetes
import data.lib.utils

default failTrustedAzureRegistry = false

__rego_metadata__ := {
	"id": "KSV032",
	"title": "Container images from non-ACR registries used",
  "version": "v1.0.0",
  "custom": {
  	"severity": "Medium"
  }
}

# getContainersWithTrustedAzureRegistry returns a list of containers
# with image from a trusted Azure registry
getContainersWithTrustedAzureRegistry[name] {
  container := kubernetes.containers[_]
  image := container.image
  # get image registry/repo parts
  image_parts := split(image, "/")
  # images with only one part do not specify a registry
  count(image_parts) > 1
  registry = image_parts[0]
  endswith(registry, "azurecr.io")
  name := container.name
}

# getContainersWithUntrustedAzureRegistry returns a list of containers
# with image from an untrusted Azure registry
getContainersWithUntrustedAzureRegistry[name] {
  name := kubernetes.containers[_].name
  not getContainersWithTrustedAzureRegistry[name]
}

# failTrustedAzureRegistry is true if a container uses an image from an
# untrusted Azure registry
failTrustedAzureRegistry {
  count(getContainersWithUntrustedAzureRegistry) > 0
}

deny[res] {
  failTrustedAzureRegistry

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should restrict container image to your specific registry domain. For Azure any domain ending in 'azurecr.io'",
      [getContainersWithUntrustedAzureRegistry[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
  res := {
    "msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "custom":  __rego_metadata__.custom
  } 
}
