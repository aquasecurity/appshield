package main

# Test spec.template.spec.hostAliases set
test_hostAliases_set {
  failHostAliases with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "hostAliases": [
            {
              "ip": "127.0.0.1",
              "hostnames": ["localhost"]
            }
          ],
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

# Test spec.template.spec.hostAliases not set
test_hostAliases_not_set {
  not failHostAliases with input as {
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
