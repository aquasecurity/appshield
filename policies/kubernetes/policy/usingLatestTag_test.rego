package main

# PASS if image tag is latest
test_using_latest_tag {
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

# PASS if image tag is not set
test_using_latest_tag_no_tag {
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

# FAIL if image tag is not set to latest
test_using_latest_tag_with_tag {
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
              "image": "mongo:3.6",
            }
          ]
        }
      }
    }
  }
}
