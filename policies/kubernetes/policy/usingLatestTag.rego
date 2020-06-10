package main

import data.lib.kubernetes

default checkUsingLatestTag = false

# getTaggedContainers returns the names of all containers which
# have tagged images.
getTaggedContainers[container] {
    allContainers := kubernetes.containers[_]
    [x, y] := split(allContainers.image, ":")
    y != "latest"
    container := allContainers.name
}

# getUntaggedContainers returns the names of all containers which
# have untagged images or images with the latest tag.
getUntaggedContainers[container] {
    container := kubernetes.containers[_].name
    not getTaggedContainers[container]
}

# checkUsingLatestTag is true if there is a container whose image tag
# is untagged or uses the latest tag.
checkUsingLatestTag {
  count(getUntaggedContainers) > 0
}

deny[msg] {
  checkUsingLatestTag

  # msg = kubernetes.format(sprintf("%s in the %s %s has an image, %s, using the latest tag", [container.name, kubernetes.kind, image_name, kubernetes.name]))

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify image tag",
      [getUntaggedContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
}
