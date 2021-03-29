package appshield.kubernetes.KSV035

import data.lib.kubernetes
import data.lib.utils

default failTrustedECRRegistry = false

__rego_metadata__ := {
     "id": "KSV035",
     "title": "Container images from non-ECR registries used",
     "version": "v1.0.0",
     "severity": "Medium",
     "type": "Kubernetes Security Check",
     "description": "Containers should only use images from trusted registries.",
     "recommended_actions": "Use images from trusted registries.",
}

# list of trusted ECR registries
trusted_ecr_registries = [
  "ecr.us-east-2.amazonaws.com",
  "ecr.us-east-1.amazonaws.com",
  "ecr.us-west-1.amazonaws.com",
  "ecr.us-west-2.amazonaws.com",
  "ecr.af-south-1.amazonaws.com",
  "ecr.ap-east-1.amazonaws.com",
  "ecr.ap-south-1.amazonaws.com",
  "ecr.ap-northeast-2.amazonaws.com",
  "ecr.ap-southeast-1.amazonaws.com",
  "ecr.ap-southeast-2.amazonaws.com",
  "ecr.ap-northeast-1.amazonaws.com",
  "ecr.ca-central-1.amazonaws.com",
  "ecr.cn-north-1.amazonaws.com.cn",
  "ecr.cn-northwest-1.amazonaws.com.cn",
  "ecr.eu-central-1.amazonaws.com",
  "ecr.eu-west-1.amazonaws.com",
  "ecr.eu-west-2.amazonaws.com",
  "ecr.eu-south-1.amazonaws.com",
  "ecr.eu-west-3.amazonaws.com",
  "ecr.eu-north-1.amazonaws.com",
  "ecr.me-south-1.amazonaws.com",
  "ecr.sa-east-1.amazonaws.com",
  "ecr.us-gov-east-1.amazonaws.com",
  "ecr.us-gov-west-1.amazonaws.com",
]

# getContainersWithTrustedECRRegistry returns a list of containers
# with image from a trusted ECR registry
getContainersWithTrustedECRRegistry[name] {
  container := kubernetes.containers[_]
  image := container.image
  # get image registry/repo parts
  image_parts := split(image, "/")
  # images with only one part do not specify a registry
  count(image_parts) > 1
  registry = image_parts[0]
  trusted := trusted_ecr_registries[_]
  endswith(registry, trusted)
  name := container.name
}

# getContainersWithUntrustedECRRegistry returns a list of containers
# with image from an untrusted ECR registry
getContainersWithUntrustedECRRegistry[name] {
  name := kubernetes.containers[_].name
  not getContainersWithTrustedECRRegistry[name]
}

# failTrustedECRRegistry is true if a container uses an image from an
# untrusted ECR registry
failTrustedECRRegistry {
  count(getContainersWithUntrustedECRRegistry) > 0
}

deny[res] {
  failTrustedECRRegistry

  msg := kubernetes.format(
    sprintf(
      "container %s of %s %s in %s namespace should restrict container image to your specific registry domain. See the full ECR list here: https://docs.aws.amazon.com/general/latest/gr/ecr.html",
      [getContainersWithUntrustedECRRegistry[_], lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
    )
  )
    res := {
    	"msg": msg,
        "id":  __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type":  __rego_metadata__.type,
    }
}
