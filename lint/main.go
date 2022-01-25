package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type RegoMetadata struct {
	ID                 string   `json:"id"`
	AVDID              string   `json:"avd_id"`
	Title              string   `json:"title"`
	Version            string   `json:"version"`
	Type               string   `json:"type"`
	Description        string   `json:"description"`
	Url                string   `json:"url"`
	Severity           string   `json:"severity"`
	RecommendedActions string   `json:"recommended_actions"`
	Links              []string `json:"-"`
}

func main() {
	var failure bool
	regoFiles, err := getAllNonTestRegoFiles()
	if err != nil {
		panic(err)
	}

	for _, file := range regoFiles {
		rego, err := ioutil.ReadFile(file)
		if err != nil {
			panic(fmt.Sprintf("file: %s, %v", file, err))
		}

		metadataReplacer := strings.NewReplacer("\n", "", "\t", "", `\\"`, `"`, ",\n}", "}")
		metadataRegex := regexp.MustCompile(`(?m)(?s)__rego_metadata__ := (\{.+?\})`)
		metadata := metadataReplacer.Replace(metadataRegex.FindStringSubmatch(string(rego))[1])
		var regoMeta RegoMetadata
		if err := json.Unmarshal([]byte(metadata), &regoMeta); err != nil {
			panic(fmt.Sprintf("file: %s, %v", file, err))
		}

		if valid, failures := valid(regoMeta); !valid {
			failure = true
			failureString := strings.Join(failures, "\n - ")
			fmt.Printf("File [%s] has invalid metadata: %s", file, failureString)
			fmt.Println()
		}
	}
	if failure {
		os.Exit(1)
	}
}

func getAllNonTestRegoFiles() ([]string, error) {
	var regoFiles []string

	if err := filepath.Walk("./", func(path string, info os.FileInfo, err error) error {

		if info.IsDir() ||
			strings.HasSuffix(info.Name(), "_test.rego") ||
			!strings.Contains(path, "/policies/") ||
			filepath.Ext(path) != ".rego" {
			return nil
		}

		regoFiles = append(regoFiles, path)

		return nil
	}); err != nil {
		return nil, err
	}

	return regoFiles, nil
}

func valid(regoMetadata RegoMetadata) (bool, []string) {
	var failureAttributes []string
	valid := true
	if strings.EqualFold(regoMetadata.AVDID, "") {
		valid = false
		failureAttributes = append(failureAttributes, "AVDID")
	}
	if strings.EqualFold(regoMetadata.ID, "") {
		valid = false
		failureAttributes = append(failureAttributes, "ID")
	}
	if strings.EqualFold(regoMetadata.Title, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Title")
	}
	if strings.EqualFold(regoMetadata.Description, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Description")
	}
	if strings.EqualFold(regoMetadata.Severity, "") {
		valid = false
		failureAttributes = append(failureAttributes, "Severity")
	}
	return valid, failureAttributes
}
