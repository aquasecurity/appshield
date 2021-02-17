package main

# Test securityContext not set
test_capsDropAny_securityContext_not_set {
  failCapsDropAny with input as {
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

# Test securityContext.capabilities.drop set
test_capsDropAny_capabilites_drop_set {
  not failCapsDropAny with input as {
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
                  "drop": ["ALL"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.capabilities.drop not set
test_capsDropAny_capabilites_drop_not_set {
  failCapsDropAny with input as {
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
                  "add": ["ALL"]
                }
              }
            }
          ]
        }
      }
    }
  }
}
