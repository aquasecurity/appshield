package main

# Test no additional capabilities
test_no_additional_caps {
  not failAdditionalCaps with input as {
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

# Test no additional capabilities
test_additional_caps {
  failAdditionalCaps with input as {
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
                "allowPrivilegeEscalation": false,
                "capabilities": {
                  "add": ["BLOCK_SUSPENDED"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

