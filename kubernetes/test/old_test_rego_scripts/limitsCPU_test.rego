package main

# Test container[].resources.limits.cpu not set
test_LimitsCPU_not_set {
  failLimitsCPU with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "hostPID": true,
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

# Test container[].resources.limits.cpu is set
test_LimitsCPU_set {
  not failLimitsCPU with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "hostPID": true,
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
              "resources": {
                "limits": {
                  "cpu": "300m"
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test container[].resources.limits.cpu any not set
test_LimitsCPU_any_not_set {
  failLimitsCPU with input as {
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
              "resources": {
                "limits": {
                  "cpu": "300m"
                }
              }
            },
            {
              "name": "app",
              "image": "app",
            }
          ]
        }
      }
    }
  }
}
