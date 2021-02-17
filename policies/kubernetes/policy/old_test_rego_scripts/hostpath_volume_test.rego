package main

# Test volume.hostPath set
test_dockerSocket_set {
  failHostPathVolume with input as {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "volumes": [
            {
              "name": "dockersock",
              "hostPath": {
                "path": "/var/run/docker.sock"
              }
            }
          ]
        }
      }
    }
  }
}

# Test volume.hostPath not set
test_dockerSocket_set {
  not failHostPathVolume with input as {
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
            },
            {
              "name": "app",
              "image": "app:v1"
            }
          ]
        }
      }
    }
  }
}
