package main

# Test seccomp profile not set
# ANY container
test_seccomp_not_set {
  failSeccomp with input as {
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

test_seccomp_any_not_set {
  failSeccomp with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
      "annotations": {
        "container.seccomp.security.alpha.kubernetes.io/carts-db":"runtime/default"
      }
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

# Test seccomp profile set to "unconfined"
# on ANY container
test_seccomp_unconfined_set {
  failSeccomp with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
      "annotations": {
        "container.seccomp.security.alpha.kubernetes.io/carts-db":"unconfined"
      }
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
          ]
        }
      }
    }
  }
}

# Test seccomp profile set
test_seccomp_set {
  not failSeccomp with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment",
      "annotations": {
        "container.seccomp.security.alpha.kubernetes.io/carts-db":"runtime/default"
      }
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
          ]
        }
      }
    }
  }
}
