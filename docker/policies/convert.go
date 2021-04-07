package main

import (
    "fmt"
    "regexp"
    "bufio"
    "os"
    "text/template"
    "strings"
	"flag"
)

var (
	inputFile string
	outputFile string
)

func init() {
	flag.StringVar(&inputFile, "in", "", "KICS query.rego file path")
	flag.StringVar(&outputFile, "out", "", "Appshield rego file path")
}

func main() {
	flag.Parse()

    p := parse(inputFile)

    tmpl, err := template.New("policy").Parse(policyTmpl)
    check(err)

	f, err := os.Create(outputFile)
    check(err)
	defer f.Close()

    err = tmpl.Execute(f, p)
    check(err)
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

var policyTmpl string = `package $namespace.$type.$policyid

__rego_metadata__ := {
    "id": "XYZ-1234",
    "title": "My rule",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "Some security check",
}

deny[res] {
    {{ .CxPolicy }}

    res := {
        "msg": "decision message",
        "id": __rego_metadata__.id,
        "title": __rego_metadata__.title,
        "severity": __rego_metadata__.severity,
        "type": __rego_metadata__.type,
    }
}

{{ range .Rules -}}{{ . }}{{ "\n"}}{{ end -}}

# vim: ts=4:sw=4:expandtab
`

type policy struct {
    CxPolicy string
    Rules []string
}

func parse(regoFile string) *policy {
    f, err := os.Open(regoFile)
    check(err)
    defer f.Close()

    scanner := bufio.NewScanner(f)
    braces := 0
    ignoredBraces := 0
    var cxPolicy string
    var isCxPolicy bool
    var isRule bool
    var isIgnored bool
    var rule string
    rules := make([]string, 1)

    for scanner.Scan() {
        line := scanner.Text()
        b_line := []byte(line)

	    //  Match CxPolicy rule header
        if match, _ := regexp.Match(`CxPolicy\[result\]`, b_line); match {
            isCxPolicy = true
            isRule = false

            if match, _ := regexp.Match(`{`, b_line); match {
                braces += 1
            }
            continue
        }

        if isCxPolicy {
            // Ignore KICS result JSON
            if match, _ := regexp.Match(`result := {`, b_line); match {
                isIgnored = true
                if match, _ := regexp.Match(`{`, b_line); match {
                    ignoredBraces += 1
                }
                continue
            }

            if isIgnored {
                if match, _ := regexp.Match(`{`, b_line); match {
                    ignoredBraces += 1
                }

                if match, _ := regexp.Match(`}`, b_line); match {
                    ignoredBraces -= 1
                }

                if ignoredBraces == 0 {
                    isIgnored = false
                }
                continue
            }
            // end ignore KICS result JSON

            if match, _ := regexp.Match(`{`, b_line); match {
                braces += 1
            }

            if match, _ := regexp.Match(`}`, b_line); match {
                braces -= 1
            }

            if braces == 0 {
                isCxPolicy = false
            } else {
                cxPolicy += fmt.Sprintf("%s\n", line)
            }
        }

        // Get non-CxPolicy rules
        if match, _ := regexp.Match(`^[a-zA-Z0-9_]+.*{`, b_line); match || isRule {
            isRule = true
            isCxPolicy = false

            rule += fmt.Sprintf("%s\n", line)

            if match, _ := regexp.Match(`{`, b_line); match {
                braces += 1
            }

            if match, _ := regexp.Match(`}`, b_line); match {
                braces -= 1
            }

            // Append rule rules slice
            if braces == 0 {
                isRule = false
                rules = append(rules, strings.TrimRight(rule, "\n"))
                rule = ""
            }
        }

    }

    if err := scanner.Err(); err != nil {
        fmt.Fprintln(os.Stderr, err)
    }

    cxPolicy = strings.TrimRight(cxPolicy, "\n")
    return &policy{CxPolicy: cxPolicy, Rules: rules}
}

// vim: ts=4:sw=4
