package main

# Test pod level seLinux opts
test_pod_selinux_options_set {
  failSELinuxOpts with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "seLinuxOptions": {
              "level": "s0:c123,c456"
            }
          },
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

# Test container level seLinux opts
test_container_selinux_options_set {
  failSELinuxOpts with input as {
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
                "seLinuxOptions": {
                  "level": "s0:c123,c456"
                }
              }
            }
          ]
        }
      }
    }
  }
}

# Test seLinux opts not set
test_selinux_options_not_set {
  not failSELinuxOpts with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
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
