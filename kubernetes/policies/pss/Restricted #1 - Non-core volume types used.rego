package appshield.kubernetes.KSV028

import data.lib.kubernetes
import data.lib.utils

__rego_metadata__ := {
	"id": "KSV028",
	"title": "Non-core volume types used.",
	"version": "v1.0.0",
	"severity": "LOW",
	"type": "Kubernetes Security Check",
	"description": "According to pod security standard 'Volume types', non-core volume types must not be used.",
	"recommended_actions": "Do not Set 'spec.volumes[*]' to any of the disallowed volume types."
}

__rego_input__ := {
  "combine": false,
  "selector": [{
    "type" : "kubernetes", "group": "core", "version": "v1", "kind": "pod"
  },
  {
   "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "replicaset"
  },
  {
    "type" : "kubernetes", "group": "core", "version": "v1", "kind": "replicationcontroller"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "deployment"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "statefulset"
  },
  {
    "type" : "kubernetes", "group": "apps", "version": "v1", "kind": "daemonset"
  },
  {
    "type" : "kubernetes", "group": "batch", "version": "v1", "kind": "cronjob"
  },
  {
    "type" : "kubernetes", "group": "batch", "version": "v1", "kind": "job"
  }]
}

# Add disallowed volume type
disallowed_volume_types = [
	"gcePersistentDisk",
	"awsElasticBlockStore",
	"hostPath",
	"gitRepo",
	"nfs",
	"iscsi",
	"glusterfs",
	"rbd",
	"flexVolume",
	"cinder",
	"cephFS",
	"flocker",
	"fc",
	"azureFile",
	"vsphereVolume",
	"quobyte",
	"azureDisk",
	"portworxVolume",
	"scaleIO",
	"storageos",
	"csi",
]

# getDisallowedVolumes returns a list of volume names
# which set volume type to any of the disallowed volume types
getDisallowedVolumes[name] {
	volume := kubernetes.volumes[_]
	type := disallowed_volume_types[_]
	utils.has_key(volume, type)
	name := volume.name
}

# failVolumeTypes is true if any of volume has a disallowed
# volume type
failVolumeTypes {
	count(getDisallowedVolumes) > 0
}

deny[res] {
	failVolumeTypes

	msg := kubernetes.format(sprintf("%s %s in %s namespace should set volume %s spec.volumes[*] to type PersistentVolumeClaim", [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, getDisallowedVolumes[_]]))

	res := {
		"msg": msg,
		"id": __rego_metadata__.id,
		"title": __rego_metadata__.title,
		"severity": __rego_metadata__.severity,
		"type": __rego_metadata__.type,
	}
}
