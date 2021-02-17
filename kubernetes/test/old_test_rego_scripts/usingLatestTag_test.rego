package main

# Test image tag is latest
test_usingLatestTag_tag_is_latest {
  checkUsingLatestTag with input as {
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
            }
          ]
        }
      }
    }
  }
}

# Test image tag is untagged
test_usingLatestTag_no_tag {
  checkUsingLatestTag with input as {
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

# Test image tag is not latest
test_usingLatestTag_tag_not_latest {
  not checkUsingLatestTag with input as {
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
              "image": "mongo:3.6",
            }
          ]
        }
      }
    }
  }
}
