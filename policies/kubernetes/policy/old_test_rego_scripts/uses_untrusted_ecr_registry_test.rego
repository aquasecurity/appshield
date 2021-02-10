package main

# Test untrusted ECR registry
test_untrusted_ecr_registry {
  failTrustedECRRegistry with input as {
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

# Test trusted ECR registry
test_trusted_ecr_registry {
  not failTrustedECRRegistry with input as {
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
              "image": "12345699.dkr.ecr.eu-west-1.amazonaws.com/travelshift/webapp",
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
  failTrustedECRRegistry with input as {
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
