package main

# Test no host ports
test_no_host_ports {
  not failHostPorts with input as {
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

# Test host ports
test_host_ports {
  failHostPorts with input as {
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
              "ports": [
                {
                  "containerPort": 8080,
                  "hostPort": 8080
                }
              ]
            }
          ],
          "initContainers": [
            {
              "name": "init-svc",
              "image": "busybox:1.28",
              "securityContext": {
                "allowPrivilegeEscalation": false,
                "capabilities": {
                  "add": ["BLOCK_SUSPENDED"]
                }
              }
            }
          ]
        }
      }
    }
  }
}

