package main

# Test securityContext.readOnlyRootFilesystem not set
test_ReadOnlyRootFilesystem_not_set {
  failReadOnlyRootFilesystem with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.readOnlyRootFilesystem is false
test_ReadOnlyRootFilesystem_is_false {
  failReadOnlyRootFilesystem with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
              "securityContext": {
                "readOnlyRootFilesystem": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.readOnlyRootFilesystem is true
test_ReadOnlyRootFilesystem_is_true {
  not failReadOnlyRootFilesystem with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
              "securityContext": {
                "readOnlyRootFilesystem": true
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.readOnlyRootFilesystem ANY not set
test_ReadOnlyRootFilesystem_any_not_set {
  failReadOnlyRootFilesystem with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
              "securityContext": {
                "readOnlyRootFilesystem": true
              }
            }
          ],
          "initContainers": [
            {
              "name": "init",
              "image": "busybox"
            }
          ]
        }
      }
    }
  }
}
