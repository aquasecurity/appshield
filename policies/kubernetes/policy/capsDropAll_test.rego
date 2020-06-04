package main

# PASS if capabilities drop does not include 'ALL'
test_caps_drop_all {
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

# PASS if capabilities is not set
test_caps_drop_all_drop_no_caps {
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

# FAIL if capability drop includes 'ALL'.
test_caps_drop_all_set_all {
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
