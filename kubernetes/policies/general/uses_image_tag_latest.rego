# @title: Image tag ":latest" used
# @description: It is best to avoid using the ":latest' image tag when deploying containers in production. Doing so makes it hard to track which version of the image is running, and hard to roll back the version.
# @recommended_actions: Use a specific container image tag that is not "latest".
# @severity: Low
# @id: KSV013
# @links: 

package appshield.KSV013

import data.lib.kubernetes

default checkUsingLatestTag = false

__rego_metadata__ := {
	"id": "KSV013",
	"title": "Image tag \":latest\" used",
  "version": "v1.0.0",
  "custom": {
  	"severity": "Low"
  }
}

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

deny[res] {
  checkUsingLatestTag

  # msg = kubernetes.format(sprintf("%s in the %s %s has an image, %s, using the latest tag", [container.name, kubernetes.kind, image_name, kubernetes.name]))

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should specify image tag",
      [getUntaggedContainers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
  res := {
    "msg": msg,
    "id":  __rego_metadata__.id,
    "title": __rego_metadata__.title,
    "custom":  __rego_metadata__.custom
  }    
}
