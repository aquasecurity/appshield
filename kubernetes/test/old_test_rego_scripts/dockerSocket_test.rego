package main

# Test volume.hostPath.path set to /var/run/docker.sock
test_dockerSocket_set {
  checkDockerSocket with input as {
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

# Test volumes.hostPath.path not set to /var/run/docker.sock
test_dockerSocket_not_set {
  not checkDockerSocket with input as {
    "kind": "Deployment",
    "spec": {
      "template": {
        "spec": {
          "volumes": [
            {
              "name": "dockersock",
              "hostPath": {
                "path": "/some/other/path"
              }
            }
          ]
        }
      }
    }
  }
}

# Test no volumes
test_dockerSocket_no_volumes {
  not checkDockerSocket with input as {
    "kind": "Deployment",
    "spec": {
    }
  }
}
