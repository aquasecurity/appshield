package main

# Test runAsGroup less than 10000
test_runasgroup_lt_10000 {
  failRunAsGroup with input as {
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
                "runAsGroup": 20
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsGroup equal to 10000
test_runasgroup_eq_10000 {
  failRunAsGroup with input as {
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
                "runAsGroup": 10000
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsGroup greater than 10000
test_runasgroup_gt_10000 {
  not failRunAsGroup with input as {
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
                "runAsGroup": 20000
              }
            }
          ]
        }
      }
    }
  }
}

# Test runAsGroup not set
test_runasgroup_not_set {
  failRunAsGroup with input as {
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


# Test runAsGroup no securityContext
test_runasgroup_no_sec_context {
  failRunAsGroup with input as {
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

# Test runAsGroup less than 10000
# ANY container
test_runasgroup_lt_10000 {
  failRunAsGroup with input as {
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
                "runAsGroup": 20000
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
