package main

# Test pod with root group id
test_pod_with_root_group_id {
  failRootGroupId with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "runAsGroup": 0
          },
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo:latest",
            }
          ]
        }
      }
    }
  }
}

# Test pod with root group id
test_pod_with_root_group_id {
  failRootGroupId with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "supplementalGroups": [0]
          },
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo:latest",
            }
          ]
        }
      }
    }
  }
}

# Test pod with root group id
test_pod_with_non_root_group_id {
  not failRootGroupId with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "fsGroup": 1500
          },
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo:latest",
            }
          ]
        }
      }
    }
  }
}

# Test container with root group id
test_container_with_root_group_id {
  names := getContainersWithRootGroupId with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo:latest",
              "securityContext": {
                "runAsGroup": 0
              }
            }
          ]
        }
      }
    }
  }

  count(names) > 0
}


# Test container with non root group id
test_container_with_non_root_group_id {
  names := getContainersWithRootGroupId with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
    },
    "spec": {
      "template": {
        "spec": {
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo:latest",
              "securityContext": {
                "runAsGroup": 1005
              }
            }
          ]
        }
      }
    }
  }

  count(names) == 0
}
