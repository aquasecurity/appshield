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
}

recommendedVersions := {
	"extensions/v1beta1": {
		"Deployment": "apps/v1",
		"DaemonSet": "apps/v1",
		"Ingress": "apps/v1",
	},
	"apps/v1beta1": {
		"Deployment": "apps/v1",
		"StatefulSet": "apps/v1",
	},
	"apps/v1beta2": {
		"Deployment": "apps/v1",
		"DaemonSet": "apps/v1",
		"StatefulSet": "apps/v1",
	},
}

# Get all containers which use deprecated api versions
getDeprecatedApi[name] {
	allContainers := kubernetes.containers[_]
	utils.has_key(recommendedVersions, kubernetes.apiVersion)
	name := allContainers.name
}

# failApiVersionCheck is true if containers[].apiVersion is deprecated
failApiVersionCheck {
	count(getDeprecatedApi) > 0
}

deny[res] {
	failApiVersionCheck

	msg := kubernetes.format(sprintf("%s %s is using deprecated 'apiVersion' %s, it sould be %s", [getDeprecatedApi[_], lower(kubernetes.kind), kubernetes.apiVersion, lower(kubernetes.kind), recommendedVersions[kubernetes.apiVersion][kubernetes.kind]]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
