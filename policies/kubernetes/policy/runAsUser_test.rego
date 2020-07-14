package main

# Test runAsUser less than 10000
test_runasuser_lt_10000 {
  failRunAsUser with input as {
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
                "runAsUser": 20
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsUser equal to 10000
test_runasuser_eq_10000 {
  failRunAsUser with input as {
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
                "runAsUser": 10000
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsUser greater than 10000
test_runasuser_gt_10000 {
  not failRunAsUser with input as {
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
                "runAsUser": 20000
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsUser not set
test_runasuser_not_set {
  failRunAsUser with input as {
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

# Test runAsUser no securityContext
test_runasuser_no_sec_context {
  failRunAsUser with input as {
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

# Test runAsUser less than 10000
# ANY container
test_runasuser_lt_10000 {
  failRunAsUser with input as {
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
                "runAsUser": 20000
              }
            }
          ],
          "initContainers": [
            {
              "name": "init",
              "image": "busybox",
            }
          ]
        }
      }
    }
  }
}
