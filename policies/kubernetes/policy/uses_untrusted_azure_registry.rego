# @title: Uses images from untrusted Azure registries.
# @description: Containers should only use images from trusted Azure registries.
# @recommended_actions: Use images from trusted Azure registries.
# @severity:
# @id:
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

default failTrustedAzureRegistry = false

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

deny[msg] {
  failTrustedAzureRegistry

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should restrict container image to your specific registry domain. For Azure any domain ending in 'azurecr.io'",
      [getContainersWithUntrustedAzureRegistry[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
