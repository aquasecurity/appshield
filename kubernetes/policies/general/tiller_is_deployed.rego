package appshield.kubernetes.KSV102

import data.lib.kubernetes

__rego_metadata__ := {
	"id": "KSV102",
	"title": "Tiller Is Deployed",
	"version": "v1.0.0",
	"severity": "Critical",
	"type": "Kubernetes Security Check",
	"description": "Check if Tiller is deployed.",
	"recommended_actions": "Remove tiller and migrate to Helm v3",
}

# Get all containers and check kubernetes metadata for tiller
tillerDeployed[container] {
	currentContainer := kubernetes.containers[_]
	checkMetadata(kubernetes.metadata)
	container := currentContainer.name
}

# Get all containers and check each image for tiller
tillerDeployed[container] {
	currentContainer := kubernetes.containers[_]
	contains(currentContainer.image, "tiller")
	container := currentContainer.name
}

# Get all pods and check each metadata for tiller
tillerDeployed[container] {
	currentPod := kubernetes.pods[_]
	checkMetadata(currentPod.metadata)
	container := currentPod.metadata.name
}

deny[res] {
	tillerDeployedContainers = tillerDeployed
	count(tillerDeployedContainers) > 0

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace shouldn't have tiller deployed", [tillerDeployed[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}

# Check for tiller in name field 
checkMetadata(metadata) {
	contains(metadata.name, "tiller")
}

# Check for tiller if app is helm
checkMetadata(metadata) {
	object.get(metadata.labels, "app", "undefined") == "helm"
}

# Check for tiller in labels.name field
checkMetadata(metadata) {
	contains(object.get(metadata.labels, "name", "undefined"), "tiller")
}
