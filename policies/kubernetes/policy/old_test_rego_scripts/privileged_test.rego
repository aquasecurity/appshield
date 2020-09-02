package main

# Test securityContext.privileged is true
test_Privileged_is_true {
  failPrivileged with input as {
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
                "privileged": true
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.privileged is false
test_Privileged_is_false {
  not failPrivileged with input as {
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
                "privileged": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test securityContext.privileged not set
test_Privileged_is_false {
  not failPrivileged with input as {
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

# Test securityContext.privileged ANY is true
test_Privileged_ANY_is_true {
  failPrivileged with input as {
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
                "privileged": true
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
