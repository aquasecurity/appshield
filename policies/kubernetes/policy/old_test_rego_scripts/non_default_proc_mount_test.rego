package main

# Test non-default procMount
test_non_default_proc_mount {
  failProcMount with input as {
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
                "procMount": "UnmaskedProcMount",
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

# Test default procMount
test_default_proc_mount {
  not failProcMount with input as {
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
                "procMount": "Default",
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
