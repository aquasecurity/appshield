package main

# PASS if volumes.hostPath.path is set to /var/run/docker.sock
test_docker_socket {
  checkDockerSocket with input as {
    "kind": "Deployment",
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

# FAIL if volumes.hostPath.path is set to some other path
test_docker_socket_some_other_volume {
  checkDockerSocket with input as {
    "kind": "Deployment",
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

# FAIL if volumes.hostPath.path is not set
test_docker_socket_no_volumes {
  checkDockerSocket with input as {
    "kind": "Deployment",
    "spec": {
    }
  }
}
