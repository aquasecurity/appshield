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

1. Default Fail rule value: This should always be set to false (required by OPA testing).
1. Fail rule: This rule checks for conditions which will result in a deny. 
   The rule name should be in the form `fail<SomeText>.
   This rule should always return true if the condition for a deny is met (required by OPA testing).
1. Deny rule: This rule should call the fail rule and return a message if the fail rule is true.

Example policy document:
```
# default fail rule value
default failFoo = false

# fail rule
failFoo {
  input.foo == "bar"
}

# deny rule
deny[msg] {
  failFoo
  msg := "Foo is denied"
}
```

Example test file:
```
test_foo {
  failFoo with input as { "foo": "bar" }
}
```

## Testing policies
To run tests:
```
cd ./policy
opa test .
```

### Concepts
Each policy document has a corresponding test file.

We explicitly write both passing and failing tests for now to test both allow and deny for various
inputs.
Our convention is to add comments beginning with PASS or FAIL to identify passing tests (deny) and
failing tests (allow) to make understanding and reviewing tests easier.

### What is a PASS test
These are tests that will make `check` rules evalute to true, therefore making the `deny` rule true.
PASS tests are useful for checking if our policy document deny on expected input.
For example in the example policy document above, `test_foo` will PASS only if input is `input.foo`.

### What is a FAIL test
These are tests that will make `check` rules evaluate to false, thereby making the `deny` rule false.
FAIL tests are useful for checking that our policy documents do not deny (allow) valid input.
For example in the example policy document above, `test_foo` will FAIL (allow) if input is anything
other than `input.foo`.

## References:
- Learn Rego here: https://www.openpolicyagent.org/docs/latest/policy-language/
- Rego playground: https://play.openpolicyagent.org/
- Writing unit tests: https://www.openpolicyagent.org/docs/latest/policy-testing/
- Easy way to run Rego policies: https://github.com/instrumenta/conftest/.
  Simply run 'docker run --rm -v $(pwd):/k8s instrumenta/conftest test /k8s/test.yaml -p /k8s/policy/'
