package main

# Test securityContext.capabilities.add includes SYS_ADMIN
test_capsSysAdmin_set {
  failCapsSysAdmin with input as {
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
                "capabilities": {
                  "add": ["SYS_ADMIN", "NET_ADMIN"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.capabilities.add does not include SYS_ADMIN
test_capsSysAdmin_not_set {
  not failCapsSysAdmin with input as {
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
                "capabilities": {
                  "add": ["NET_ADMIN"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.capabilities.add not set
test_capsSysAdmin_not_set_2 {
  not failCapsSysAdmin with input as {
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
                "capabilities": {
                  "drop": ["NET_ADMIN"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.capabilities not set
test_capsSysAdmin_not_set_3 {
  not failCapsSysAdmin with input as {
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
                "runAsNonRoot": true
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext not set
test_capsSysAdmin_not_set_4 {
  not failCapsSysAdmin with input as {
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
            }
          ]
        }
      }
    }
  }
}
