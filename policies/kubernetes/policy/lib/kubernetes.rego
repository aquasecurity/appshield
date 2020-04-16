package lib.kubernetes

default is_gatekeeper = false

is_gatekeeper {
	has_field(input, "review")
	has_field(input.review, "object")
}

object = input {
	not is_gatekeeper
}

object = input.review.object {
	is_gatekeeper
}

format(msg) = gatekeeper_format {
	is_gatekeeper
	gatekeeper_format = {"msg": msg}
}

format(msg) = msg {
	not is_gatekeeper
}

name = object.metadata.name

kind = object.kind

is_service {
	kind = "Service"
}

is_deployment {
	kind = "Deployment"
}

is_pod {
	kind = "Pod"
}

split_image(image) = [image, "latest"] {
	not contains(image, ":")
}

split_image(image) = [image_name, tag] {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) = all_containers {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers[container] {
	all_containers = pod_containers(object)
	container = all_containers[_]
}

pods[pod] {
	is_deployment
	pod = object.spec.template
}

pods[pod] {
	is_pod
	pod = object
}

volumes[volume] {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
	container.securityContext.capabilities.add[_] == cap
}

has_field(obj, field) {
	obj[field]
}

no_read_only_filesystem(c) {
	not has_field(c, "securityContext")
}

no_read_only_filesystem(c) {
	has_field(c, "securityContext")
	not has_field(c.securityContext, "readOnlyRootFilesystem")
}

priviledge_escalation_allowed(c) {
	not has_field(c, "securityContext")
}

priviledge_escalation_allowed(c) {
	has_field(c, "securityContext")
	has_field(c.securityContext, "allowPrivilegeEscalation")
}