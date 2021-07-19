package appshield.kubernetes.KSV037

import data.lib.kubernetes
default failExternalIPs = false

__rego_metadata__ := {
     "id": "KSV037",
     "title": "Service with External IP",
     "version": "v1.0.0",
     "severity": "High",
     "type": "Kubernetes Security Check",
     "description": "Services with external IP addresses allows direct access from the internet and might expose risk for CVE-2020-8554",
     "recommended_actions": "Do not set spec.externalIPs"
}

allowedIPs = set()
# failExternalIPs is true if service has external IPs
failExternalIPs {
  kubernetes.kind == "Service"
  externalIPs := {ip | ip := kubernetes.object.spec.externalIPs[_]}
  forbiddenIPs := externalIPs - allowedIPs
  count(forbiddenIPs) > 0
}
deny[res] {
  failExternalIPs
  msg := kubernetes.format(
    sprintf("%s %s in %s namespace should not set external IPs",
      [ lower(kubernetes.kind), kubernetes.name, kubernetes.namespace]
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
