The most comperhensive REGO library for Kubernetes workload configuration checks

Examples:
- Use tools such as OPA Gatekeeper and Conftes that support REGO to check kubernetes resources configurations
- Ensure pods and controllers are not running as privileged
- Ensure pods images are hosted in a trusted ECR/GCR/ACR registry
- and more checks to comply with PSP, PSS and additional standards

# Quick start
Follow these steps to pull a policy and test Kubernetes workload manifest:
1. Create a directory named "myPolicy" to host all the required rego checks

```
mkdir myPolicy
```
2. Download the main library and the desired checks(s) into "policy" directory - in this example we use the "is_privileged" check only
```
wget https://github.com/aquasecurity/appshield/raw/master/policies/kubernetes/policy/lib/kubernetes.rego
wget https://github.com/aquasecurity/appshield/raw/master/policies/kubernetes/policy/lib/utils.rego
wget https://github.com/aquasecurity/appshield/raw/master/policies/kubernetes/policy/is_privileged.rego
```
3. Download an example of a non-compliant kubernetes deployment (in yaml format) 
```
wget https://github.com/aquasecurity/appshield/raw/master/policies/kubernetes/test.yaml
```
4. Use any tool that supports REGO to test the exmple file. In this example we are using conftest
```
conftest test test.yaml --policy myPolicy/
```

# Standards and Use-cases
The controls of both Pod Security Policy (PSP) and Pod Security Standards (PSS) and additional best practices are covered in this github repository

## PSS and PSP
Pod Security Standard (PSP) are the official standards that can replace the PSP feature
https://kubernetes.io/docs/concepts/security/pod-security-standards/

It has 14 controls that are grouped into two policies: Baseline and Restricted

We chose to name the controls in this repository under the PSS controls that are more up to date and has better coverage than PSP.
The following table compare PSS to PSP:

### PSS - baseline

PSS control | PSP control(s)
------------ | -------------
1-Host Namespaces | 2-Usage of host namespaces. 3-Usage of host networking and ports
2-Privileged Containers |	1-Running of privileged containers
3-Capabilities | 11-Linux capabilities
4-HostPath Volumes | 5-Usage of the host filesystem
5-Host Ports | Not covered in PSP
6-AppArmor (optional)	| 14-The AppArmor profile used by containers
7-SELinux (optional)	| 12-The SELinux context of the container
8-/proc Mount Type	| 13-The Allowed Proc Mount types for the container
9-Sysctls	| 16-The sysctl profile used by containers

### PSS - restricted

PSS control | PSP control
------------ | -------------
1-Volume Types | 4-Usage of volume types 6-Allow specific FlexVolume drivers. 8-Requiring the use of a read-only root file system
2-Privilege Escalation | 10-Restricting escalation to root privileges
3-Running as Non-root | Not covered in PSP
4-Non-root groups | 7-Allocating an FSGroup that owns the Pod's volumes. 9-The user and group IDs of the container
5-Seccomp | 15-The seccomp profile used by containers

## Additional best practices
To support more best practices we have added more REGO checks in the following directory: 
https://github.com/aquasecurity/appshield/tree/master/policies/kubernetes/policy


