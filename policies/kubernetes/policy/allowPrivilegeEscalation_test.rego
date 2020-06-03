package main

# PASS if allowPrivilegeEscalation is set to true
test_allow_privilege_escalation {
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

# PASS if securityContext.allowPrivilegeEscalation is not set
test_allow_privilege_escalation_not_set {
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

# FAIL if allowPrivilegeEscalation is set to false
test_allow_privilege_escalation_set_to_false {
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
                "allowPrivilegeEscalation": false,
                "runAsNonRoot": false
              }
            }
          ]
        }
      }
    }
  }
}

