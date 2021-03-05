# @title: Container images from public registries used
# @description: Container images must not start with an empty prefix or a defined public registry domain.
# @recommended_actions: Use images from private registries.
# @severity: Medium
# @id: KSV034
# @links:

package main

import data.lib.kubernetes
import data.lib.utils

default failPublicRegistry = false

# list of untrusted public registries
untrusted_public_registries = [
  "docker.io",
  "ghcr.io",
]

# getContainersWithPublicRegistries returns a list of containers
# with public registry prefixes
getContainersWithPublicRegistries[name] {
  container := kubernetes.containers[_]
  image := container.image
  untrusted := untrusted_public_registries[_]
  startswith(image, untrusted)
  name := container.name
}

# getContainersWithPublicRegistries returns a list of containers
# with image without registry prefix
getContainersWithPublicRegistries[name] {
  container := kubernetes.containers[_]
  image := container.image
  image_parts := split(image, "/") # get image registry/repo parts
  count(image_parts) > 0
  not contains(image_parts[0], ".") # check if first part is a url (assuming we have "." in url)
  name := container.name
}

# failPublicRegistry is true if a container uses an image from an
# untrusted public registry
failPublicRegistry {
  count(getContainersWithPublicRegistries) > 0
}

deny[msg] {
  failPublicRegistry

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should restrict container image to use private registries",
      [getContainersWithPublicRegistries[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
