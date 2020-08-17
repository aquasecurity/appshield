# @title: Avoid using the ':latest' tag
# @description: You should avoid using the :latest tag when deploying containers in production, because this makes it hard to track which version of the image is running and hard to roll back.
# @recommended_actions: Use a specific container image tag that is not 'latest' 
# @severity: Low
# @id: KSV013
# @links: 

package main

import data.lib.kubernetes

meta_ksv013 = {
  "title": "Avoid using the ':latest' tag",
  "description": "You should avoid using the :latest tag when deploying containers in production, because this makes it hard to track which version of the image is running and hard to roll back.",
  "recommended_actions": "Use a specific container image tag that is not 'latest' ",
  "severity": "Low",
  "id": "KSV013",
  "links": ""
}

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
  msg := json.marshal(meta_ksv013)
}
