# Aqua rego conventions

**version: 2**

## Policy Metadata

Rational: information that describes the policy, for policy authors and for automated tools that interact with the policy.

Each rego file MUST have a rule like the following:

```rego
__rego_metadata__ := {
    "id": "XYZ-1234",
    "apiVersion": 2,
    "version": 1,
    "title": "My rule",
    "description": "It is a good practice to do something",
    "custom": {
      "severity": "HIGH",
      "urls": ["policy-related-link.com", "more-relate-info.com"]
    }
}
```

1. Rule MUST be the first rule in the document.
2. Rule name MUST be `__rego_metadata__`.
3. Value MUST be JSON literal. In other words, it cannot use Rego expressions.
4. Rule MUST have the fields: "id", "title", "apiVersion", "version", "description". 
    - "id" field MUST be restricted to `[A-Z]3[-]1[0-9]+`. 
    - "apiVersion" field MUST be a int. This field is the version of this Rego Convensions document.
    - "version" field MUST be a int. This field changes ever time the content of the policy changes.
    - "title" field MUST be a string.
    - "description" fiels Must be a string.
10. Rule CAN have any other fields within the "custom" field's map.
    - "severity" field MUST be one of three `CRITICAL`|`HIGH`|`MEDIUM`|`LOW`|.
    - "urls" field is an array of string URLs that relate to the policy.

## Policy Input

Rational: declaration of what what input the policy expects.

Each rego file MUST have a rule like the following:

```rego
__rego_input__ := {
    "combine": false,
    "selector": [
        {
          "type": "kubernetes",
          "group": "batch",
          "version": "v1", 
          "kind": "job"
        }
    ]
}
```

1. The rule MUST be the second rule in the document (after `__rego_metadata__`).
1. The rule name MUST be `__rego_input__`.
1. The value MUST be JSON literal. In other words, it cannot use Rego expressions.
1. The rule CAN have the fields: "combine".
1. "combine" field MUST be boolean. If it is not specified, it would default to `false`.
    1. This field declares if the policy expects compound input (multiple documents) or a simple single input. 
1. The rule MUST have the fields: "selector". 
    1. "selector" field MUST be an array of "selector object".
    2. This field declares a subset of inputs that are relevant for this policy. The evaluator CAN use this information to optimize it's operation.
    3. "selector object" MUST have the following fields: "type".
    4. "selector object" CAN have additional fields. If specified they narrow the scope of applicable inputs.
    5. For Kubernetes selector, "selector object" SHOULD include the following fields: "group", "version", "kind", which are well-known Kubernetes type specifiers.
    6. If the "selector" array is empty, it is applicable to ALL input types.

*Note* when in "combine" mode, the policy is expect to have multiple input files.
The input document MUST follow the following schema:

```
[
  {
    "contents": <raw first resource to evaluate>,
    "source": <original first data source>
  },
  {
    "contents": <raw second resource to evaluate>,
    "source": <original second data source>
  },
  ...
]
```
See next section about output format when using "combine"

## Policy output

The policy's entrypoint is the rule that is evaluated in order to query the policy decision. 

The entrypoint MUST follow the following format:

```rego
deny[res] {
    # checks...
    
    res := "decision message"
    # OR    
    res := { "msg": "decision message", "extra": "information" }
    # OR
    res := { "msg": "decision message", "source": input[i].source, "extra": "information" } 
}
```

1. The entrypoint MUST be a "partial set" rule.
1. The entrypoint's result MUST be a string or an object with the fields: "msg", and optionally additional fields.
1. The string result or "msg" field is a user friendly message that describes the policy's decision.
1. In "combine" mode, the result object MUST contain a "source" field indicating which input file this decision refers to.
1. The entrypoint SHOULD be tested for it's correctness, and it MUST be tested for returning a valid result in the desired format.


## Policy files

1. The Rego package name MUST be in the format of `$namespace.$group.$policyid`. 
    1. `$namespace` indicates a bounded domain which this policy belongs to. For example: `appshield`, `tracee`.
    1. `$group` is a user provided name used for organizational purposes. The evaluator SHOULD group findings by this name. For example: `docker`, `kubernetes`, `terraform `
    1. `$policyid` is the `__rego_metadata__.id` field. If "id" contains `-`, it must be translated into `_` (due to rego's package name constraints).
1. Policies MUST have an accompanied test file with the `_test` prefix.

## Style guide

When constructing literal objects, we prefer to NOT end them with tailing comma (Rego allows both styles). For example:

```rego
my := {
  "foo": "bar",
  "hello: "world" #<-- do not add a comma here, even though it's allowed by rego
}
```
