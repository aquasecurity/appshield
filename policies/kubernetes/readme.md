We would like to write Rego policies that validates Kubernetes deployments (yaml files).
For this we would like to have the following:

1. Implement 49 policies that checks Kubernetes security.
2. Policies are implemented in Rego. One policy per Rego file.
3. The list of policies can be taken from https://github.com/controlplaneio/kubesec/tree/master/pkg/rules (total of 49 tests). Each policy should be converted to a Rego policy.
4. When running a test that did not pass, I would like us to print a message that includes:
name space name, controller/pod name, severity of test. 
5. The Rego policies should have unit tests that checks their validity.

## Policy Document Structure
All policy document should have the following sections to make it easier
to read, verify and test policies.

1. Default Check rule value: This should always be set to false (required by OPA testing).
1. Check rule: This rule checks for the condition which will result in a deny. 
   The rule name should be in the form `check<SomeText>.
   This rule should always return true if the condition for a deny is met (required by OPA testing).
1. Deny rule: This rule should call the check rule and return a message if the check rule is true.

Example policy document:
```
# default check rule value
default checkFoo = false

# check rule
checkFoo {
  input.foo == "bar"
}

# deny rule
deny[msg] {
  checkFoo
  msg := "Foo is denied"
}
```

Example test file:
```
test_foo {
  checkFoo with input as { "foo": "bar" }
}
```

## Testing policies
To run tests:
```
cd ./policy
opa test .
```

## References:
- Learn Rego here: https://www.openpolicyagent.org/docs/latest/policy-language/
- Rego playground: https://play.openpolicyagent.org/
- Writing unit tests: https://www.openpolicyagent.org/docs/latest/policy-testing/
- Easy way to run Rego policies: https://github.com/instrumenta/conftest/.
  Simply run 'docker run --rm -v $(pwd):/k8s instrumenta/conftest test /k8s/test.yaml -p /k8s/policy/'
