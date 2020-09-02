package main

# Test runAsNonRoot ANY container set to false
test_runAsNonroot_any_is_false {
  checkRunAsNonRoot with input as {
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
          ],
          "initContainers": [
            {
              "name": "carts-init",
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

# Test runAsNonRoot not set
test_runAsNonroot_not_set {
  checkRunAsNonRoot with input as {
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
              "image": "mongo"
            }
          ]
        }
      }
    }
  }
}

# Test runAsNonRoot not set
test_runAsNonroot_not_set_2 {
  checkRunAsNonRoot with input as {
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
                "allowPrivilegeEscalation": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsNonRoot is set to true
test_runAsNonroot_is_true {
  not checkRunAsNonRoot with input as {
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
