We would like to write Rego policies that validates Kubernetes deployments (yaml files).
For this we would like to have the following:

1. Implement 49 policies that checks Kubernetes security.
2. Policies are implemented in Rego. One policy per Rego file.
3. The list of policies can be taken from https://github.com/controlplaneio/kubesec/tree/master/pkg/rules (total of 49 tests). Each policy should be converted to a Rego policy.
3. The Rego policies should have unit tests that checks their validity.

References:
- Learn Rego here: https://www.openpolicyagent.org/docs/latest/policy-language/
- Rego playground: https://play.openpolicyagent.org/
- Writing unit tests: https://www.openpolicyagent.org/docs/latest/policy-testing/
- Easy way to run Rego policies: https://github.com/instrumenta/conftest/. Simply run 'docker run --rm -v $(pwd):/k8s instrumenta/conftest test /k8s/deployment.yaml -p /k8s/policy/'
