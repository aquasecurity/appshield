package main

# Test capabilities drop does not include 'ALL'
test_capsDropAll_not_include_ALL {
  checkCapsDropAll with input as {
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

# Test capabilities drop not set
test_capsDropAll_caps_drop_not_set {
  checkCapsDropAll with input as {
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

# Test capability drop includes 'ALL'.
test_capsDropAll_include_ALL {
  not checkCapsDropAll with input as {
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
                  "drop": [
                    "NET_ADMIN",
                    "SYS_TIME",
                    "ALL"
                  ]
                }
              }
            }
          ]
        }
      }
    }
  }
}
