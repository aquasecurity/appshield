package main

# Test volume type set to gcePersistentDisk
test_volume_type_gcepd {
  failVolumeTypes with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "volumes": [
            {
              "name": "mygcepd",
              "gcePersistentDisk": {
                "pdName": "my-pdname"
              }
            }
          ],
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
            }
          ]
        }
      }
    }
  }
}

# Test volume type set to PersistentVolumeClaim
test_volume_type_pvc {
  not failVolumeTypes with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "volumes": [
            {
              "name": "mypv",
              "PersistentVolumeClaim": {
                "claimName": "my-pvc"
              }
            }
          ],
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
            }
          ]
        }
      }
    }
  }
}

test_volume_type_mixed {
  failVolumeTypes with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "volumes": [
            {
              "name": "mypv",
              "PersistentVolumeClaim": {
                "claimName": "my-pvc"
              }
            },
            {
              "name": "mygcepd",
              "gcePersistentDisk": {
                "pdName": "my-pdname"
              }
            }
          ],
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
            }
          ]
        }
      }
    }
  }
}
