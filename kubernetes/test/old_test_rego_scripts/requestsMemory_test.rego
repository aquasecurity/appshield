package main

# Test container[].resources.requests.memory not set
test_RequestsMemory_not_set {
  failRequestsMemory with input as {
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

# Test container[].resources.requests.memory is set
test_RequestsMemory_set {
  not failRequestsMemory with input as {
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
                "requests": {
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

# Test container[].resources.requests.memory any not set
test_RequestsMemory_any_not_set {
  failRequestsMemory with input as {
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
                "requests": {
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
