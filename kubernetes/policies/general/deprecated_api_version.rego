package appshield.kubernetes.KSV101

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV101",
	"title": "Using A Deprecated API Version",
	"version": "v1.0.0",
	"severity": "Critical",
	"type": "Kubernetes Security Check",
	"description": "Check if any objects are using a deprecated version of API.",
	"recommended_actions": "Don't use deprecated API versions",
	"url": "https://kubernetes.io/docs/reference/using-api/deprecation-guide/",
}

__rego_input__ := {
	"combine": false,
	"selector": [{"type": "kubernetes"}],
}

recommendedVersions := {
	"extensions/v1beta1": {
		"Deployment": "apps/v1",
		"DaemonSet": "apps/v1",
		"Ingress": "apps/v1",
		"NetworkPolicy": "networking.k8s.io/v1",
		"ReplicaSet": "apps/v1",
		"PodSecurityPolicy": "policy/v1beta1",
	},
	"apps/v1beta1": {
		"Deployment": "apps/v1",
		"StatefulSet": "apps/v1",
		"ReplicaSet": "apps/v1",
	},
	"apps/v1beta2": {
		"Deployment": "apps/v1",
		"DaemonSet": "apps/v1",
		"StatefulSet": "apps/v1",
		"ReplicaSet": "apps/v1",
	},
}

deny[res] {
	utils.has_key(recommendedVersions, kubernetes.apiVersion)
	utils.has_key(recommendedVersions[kubernetes.apiVersion], kubernetes.kind)
	msg := kubernetes.format(sprintf("%s is using deprecated 'apiVersion: %s', it should be 'apiVersion: %s'", [lower(kubernetes.name), kubernetes.apiVersion, recommendedVersions[kubernetes.apiVersion][kubernetes.kind]]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
