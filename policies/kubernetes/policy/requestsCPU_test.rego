package main

# Test container[].resources.requests.cpu not set
test_RequestsCPU_not_set {
  failRequestsCPU with input as {
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

# Test container[].resources.requests.cpu is set
test_RequestsCPU_set {
  not failRequestsCPU with input as {
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

# Test container[].resources.requests.cpu any not set
test_RequestsCPU_any_not_set {
  failRequestsCPU with input as {
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
