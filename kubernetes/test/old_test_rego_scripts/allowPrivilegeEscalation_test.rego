package main

# Test allowPrivilegeEscalation is set to true on
# ANY container
test_allowPrivilegeEscalation_ANY_is_true {
  checkAllowPrivilegeEscalation with input as {
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
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": true
              }
            }
          ],
          "initContainers": [
            {
              "name": "init-svc",
              "image": "busybox:1.28",
              "securityContext": {
                "allowPrivilegeEscalation": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.allowPrivilegeEscalation is not set
# on A container
test_allowPrivilegeEscalation_not_set {
  checkAllowPrivilegeEscalation with input as {
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

# Test securityContext.allowPrivilegeEscalation is not set
# on A container
test_allowPrivilegeEscalation_not_set_2 {
  checkAllowPrivilegeEscalation with input as {
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
                "runAsNonRoot": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test allowPrivilegeEscalation is set to false on ALL
# containers
test_allowPrivilegeEscalation_ALL_is_false {
  not checkAllowPrivilegeEscalation with input as {
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
                "allowPrivilegeEscalation": false,
                "runAsNonRoot": false
              }
            },
            {
              "name": "app",
              "image": "app:v1",
              "securityContext": {
                "allowPrivilegeEscalation": false,
              }
            }
          ]
        }
      }
    }
  }
}

