package main

# Test untrusted public registry
test_untrusted_public_registry {
  failPublicRegistry with input as {
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
            }
          ]
        }
      }
    }
  }
}

# Test untrusted public registry
test_untrusted_public_registry {
  failPublicRegistry with input as {
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
              "image": "ghcr.io/nginx:15",
            }
          ]
        }
      }
    }
  }
}

# Test untrusted public registry
test_untrusted_public_registry {
  failPublicRegistry with input as {
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
              "image": "nginx/nginx:15",
            }
          ]
        }
      }
    }
  }
}

# Test untrusted public registry
test_untrusted_public_registry {
  failPublicRegistry with input as {
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
              "image": "nginx",
            }
          ]
        }
      }
    }
  }
}
