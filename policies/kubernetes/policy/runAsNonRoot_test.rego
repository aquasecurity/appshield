package main

# PASS if runAsNonRoot is set to false
test_run_as_nonroot {
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

# PASS if runAsNonRoot is not set
test_run_as_nonroot_not_set {
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

# FAIL if runAsNonRoot is set to true
test_run_as_nonroot_set_to_true {
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
                "runAsNonRoot": true
              }
            }
          ]
        }
      }
    }
  }
}