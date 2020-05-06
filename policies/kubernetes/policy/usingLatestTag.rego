package main

import data.lib.kubernetes

name = input.metadata.name

default checkUsingLatestTag = false

# checkUsingLatestTag is true if there is a container image tag
# set to latest or if the image has no tag.
checkUsingLatestTag {
  kubernetes.containers[container]
  [image_name, tag] := kubernetes.split_image(container.image)
  tag == "latest"
}

deny[msg] {
  kubernetes.containers[container]
  [image_name, tag] := kubernetes.split_image(container.image)
  msg = kubernetes.format(sprintf("%s in the %s %s has an image, %s, using the latest tag", [container.name, kubernetes.kind, image_name, kubernetes.name]))
}
