package main

# Test set disallowed sysctls
test_set_disallowed_sysctls {
  failSysctls with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "sysctls": [
              {"name": "foo.bar", "value": "bar.baz"}
            ]
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

# Test set allowed sysctls
test_set_allowed_sysctls {
  not failSysctls with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "sysctls": [
              { "name": "kernel.shm_rmid_forced", "value": "0"},
              { "name": "net.ipv4.ping_group_range", "value": "140"}
            ]
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

# Test sysctls not set
test_sysctls_not_set {
  not failSysctls with input as {
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
