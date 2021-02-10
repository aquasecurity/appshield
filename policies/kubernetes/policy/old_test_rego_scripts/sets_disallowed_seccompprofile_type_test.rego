package main

# Test disallowed pod seccomp profile type
test_disallowed_pod_seccomp_profile_type {
  failSeccompProfileType with input as {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
      "name": "mongo-deployment"
    },
    "spec": {
      "template": {
        "spec": {
          "securityContext": {
            "seccompProfile": {
              "type": "Localhost",
              "localhostProfile": "my-profiles/profile-allow.json"
            }
          },
          "containers": [
            {
              "name": "carts-db",
              "image": "mongo",
              "securityContext": {
                "runAsNonRoot": false
              }
            }
          ]
        }
      }
    }
  }
}

# Test disallowed container seccomp profile type
test_disallowed_container_seccomp_profile_type {
  containers := getContainersWithDisallowedSeccompProfileType with input as {
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
                "seccompProfile": {
                  "type": "Localhost",
                  "localhostProfile": "my-profile/profile-allow.json"
                },
                "runAsNonRoot": false
              }
            }
          ]
        }
      }
    }
  }

  count(containers) > 0
}
