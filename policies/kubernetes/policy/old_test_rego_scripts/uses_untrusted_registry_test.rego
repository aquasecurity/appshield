package main

# Test untrusted registry
test_untrusted_registry {
  failTrustedRegistry with input as {
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
              "image": "docker.io/mongo",
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

# Test trusted registry
test_trusted_registry {
  not failTrustedRegistry with input as {
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
              "image": "my.azurecr.io/mongo",
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

# Test bare image
test_bare_image {
  failTrustedRegistry with input as {
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
              "image": "mongo:latest",
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
