package main

# Test container[].resources.limits.memory not set
test_LimitsMemory_not_set {
  failLimitsMemory with input as {
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

# Test container[].resources.limits.memory is set
test_LimitsMemory_set {
  not failLimitsMemory with input as {
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
                  "memory": "300M"
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test container[].resources.limits.memory any not set
test_LimitsMemory_any_not_set {
  failLimitsMemory with input as {
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
                  "memory": "300M"
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
