package appshield.kubernetes.KSV002

import data.lib.kubernetes

default failAppArmor = false

__rego_metadata__ := {
	"id": "KSV002",
	"title": "AppArmor policies disabled",
	"version": "v1.0.0",
	"severity": "MEDIUM",
	"type": "Kubernetes Security Check",
	"description": "A program inside the container can bypass AppArmor protection policies.",
	"recommended_actions": "Remove 'container.apparmor.security.beta.kubernetes.io' annotation or set it to 'runtime/default'.",
	"url": "https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

get_app_armor_keys[key] {
	key := sprintf("%s/%s", [
		"container.apparmor.security.beta.kubernetes.io",
		kubernetes.containers[_].name,
	])
}

get_app_armor := object.filter(kubernetes.annotations[_], get_app_armor_keys)

# no container.apparmor.security.beta.kubernetes.io at all
get_apparmor_containers[container] {
	key := get_app_armor_keys[_]
	not get_app_armor
	[_, c] := split(key, "/")
	container := c
}

# container has no container.apparmor.security.beta.kubernetes.io annotation (but others have) 
get_apparmor_containers[container] {
	key := get_app_armor_keys[_]

	not get_app_armor[key]

	[_, c] := split(key, "/")
	container := c
}

# container has container.apparmor.security.beta.kubernetes.io annotation set to runtime/default
get_apparmor_containers[container] {
	key := get_app_armor_keys[_]
	val := get_app_armor[key]
	val == "runtime/default"

	[_, c] := split(key, "/")
	container := c
}

get_no_apparmor_containers[container] {
	container := kubernetes.containers[_].name
	not get_apparmor_containers[container]
}

fail_apparmor {
	count(get_no_apparmor_containers) > 0
}

deny[res] {
	fail_apparmor

	msg := kubernetes.format(sprintf("container %s of %s %s in %s namespace should specify an AppArmor profile", [get_no_apparmor_containers[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
