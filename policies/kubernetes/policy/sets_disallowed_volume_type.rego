# @title: Sets disallowed volume type.
# @description: Restrict usage of non-core volume types to those defined through PersistentVolumes.
# @recommended_actions: Do not Set 'spec.volumes[*]' to any of the disallowed volume types.
# @severity:
# @id:
# @links: 

package main

import data.lib.kubernetes
import data.lib.utils

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
  "csi"
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

deny[msg] {
  failVolumeTypes

  msg := kubernetes.format(
    sprintf(
      "%s %s in %s namespace should set volume %s spec.volumes[*] to type PersistentVolumeClaim" ,
      [lower(kubernetes.kind), kubernetes.name, kubernetes.namespace, getDisallowedVolumes[_]]
    )
  )
}
