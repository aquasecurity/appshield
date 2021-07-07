package integration_test

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

func TestDockerfile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		filePatterns []string
		want         []types.Misconfiguration
	}{
		{
			name:  "DS001: latest tag",
			input: "testdata/DS001",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS001",
							Message:   "Specify a tag in the 'FROM' statement for image 'debian'",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS001",
								Type:     "Dockerfile Security Check",
								Title:    "Use a tag name in the 'FROM' statement",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS002: root user",
			input: "testdata/DS002",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS002",
							Message:   "Specify at least 1 USER command in Dockerfile with non-root user as argument",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS002",
								Type:     "Dockerfile Security Check",
								Title:    "Image user should not be 'root'",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS004: Exposing Port 22",
			input: "testdata/DS004",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS004",
							Message:   "Port 22 is exposed via the Dockerfile",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS004",
								Type:     "Dockerfile Security Check",
								Title:    "Exposing port 22",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS005: COPY Instead of ADD",
			input: "testdata/DS005",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS005",
							Message:   `Consider using 'COPY "/target/app.jar" "app.jar"' command instead of 'ADD "/target/app.jar" "app.jar"'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS005",
								Type:     "Dockerfile Security Check",
								Title:    "Use COPY instead of ADD",
								Severity: "LOW",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS006: COPY '--from' references current image FROM alias",
			input: "testdata/DS006",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS006",
							Message:   `'COPY --from' shouldn't mention current alias 'dep' since it is impossible to copy from itself`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS006",
								Type:     "Dockerfile Security Check",
								Title:    "COPY '--from' references the current image",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS007: Multiple ENTRYPOINT Instructions Listed",
			input: "testdata/DS007",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS007",
							Message:   "There are 2 duplicate ENTRYPOINT instructions for stage 'golang:1.7.3 as dep'",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS007",
								Type:     "Dockerfile Security Check",
								Title:    "Multiple ENTRYPOINT instructions listed",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS008: UNIX Ports Out Of Range",
			input: "testdata/DS008",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS008",
							Message:   `'EXPOSE' contains port which is out of range [0, 65535]: 65536`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS008",
								Type:     "Dockerfile Security Check",
								Title:    "UNIX ports out of range",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS009: WORKDIR Path Not Absolute",
			input: "testdata/DS009",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS009",
							Message:   `WORKDIR path 'path/to/workdir' isn't absolute`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS009",
								Type:     "Dockerfile Security Check",
								Title:    "WORKDIR path not absolute",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS010: Run Using Sudo",
			input: "testdata/DS010",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS010",
							Message:   `Using 'sudo' in Dockerfile should be avoided`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS010",
								Type:     "Dockerfile Security Check",
								Title:    "Avoid using 'sudo' in containers",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS011: Copy With More Than Two Arguments Not Ending With Slash",
			input: "testdata/DS011",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS011",
							Message:   `Slash is expected at the end of COPY command argument 'myapp'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS011",
								Type:     "Dockerfile Security Check",
								Title:    "COPY with more than two arguments not ending with slash",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS012: Same Alias In Different Froms",
			input: "testdata/DS012",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS012",
							Message:   `Duplicate aliases 'build' found in different FROMs`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS012",
								Type:     "Dockerfile Security Check",
								Title:    "Same alias in different FROMs",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS013: RUN Instruction Using 'cd' Instead of WORKDIR",
			input: "testdata/DS013",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS013",
							Message:   `RUN shouldn't be used to change directory: 'cd /usr/share/nginx/html'. Use 'WORKDIR' statement instead.`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS013",
								Type:     "Dockerfile Security Check",
								Title:    "Use 'WORKDIR' instead of 'RUN cd ...'",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS014: Run Using 'wget' and 'curl'",
			input: "testdata/DS014",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS014",
							Message:   `Shouldn't use both curl and wget`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS014",
								Type:     "Dockerfile Security Check",
								Title:    "Run using 'wget' and 'curl'",
								Severity: "LOW",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS015: Yum Clean All Missing",
			input: "testdata/DS015",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS015",
							Message:   `'yum clean all' is missed: yum install vim`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS015",
								Type:     "Dockerfile Security Check",
								Title:    "Yum Clean All Missing",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS016: Multiple CMD Instructions Listed",
			input: "testdata/DS016",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS016",
							Message:   `There are 2 duplicate CMD instructions for stage 'golang:1.7.3'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS016",
								Type:     "Dockerfile Security Check",
								Title:    "Multiple CMD instructions listed",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS017: Update Instruction Alone",
			input: "testdata/DS017",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS017",
							Message:   `Instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement.`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS017",
								Type:     "Dockerfile Security Check",
								Title:    "Update instruction alone",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS018: COPY '--from' Without FROM Alias Defined Previously",
			input: "testdata/DS018",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS018",
							Message:   `The alias '--from=dep' is not defined in the previous stages`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS018",
								Type:     "Dockerfile Security Check",
								Title:    "'COPY --from' without FROM alias defined previously",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS019: Missing Dnf Clean All",
			input: "testdata/DS019",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS019",
							Message:   `'dnf clean all' is missed: set -uex &&     dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo &&     sed -i 's/\\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo &&     dnf install -vy docker-ce`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS019",
								Type:     "Dockerfile Security Check",
								Title:    "'dnf clean all' is missing after installing packages",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS020: Missing Zypper Clean",
			input: "testdata/DS020",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS020",
							Message:   `'zypper clean' is missed: 'zypper install bash'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS020",
								Type:     "Dockerfile Security Check",
								Title:    "'zypper clean' is missing after running zypper",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS021: APT-GET Missing '-y' To Avoid Manual Input",
			input: "testdata/DS021",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS021",
							Message:   `'-y' flag is missed: 'apt-get install apt-utils && apt-get clean'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS021",
								Type:     "Dockerfile Security Check",
								Title:    "'apt-get' is missing '-y' to avoid manual input",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS022: MAINTAINER is deprecated",
			input: "testdata/DS022",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS022",
							Message:   "MAINTAINER should not be used: 'MAINTAINER Lukas Martinelli <me@lukasmartinelli.ch>'",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS022",
								Type:     "Dockerfile Security Check",
								Title:    "Deprecated MAINTAINER is used",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS023: Multiple HEALTHCHECK instructions",
			input: "testdata/DS023",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS023",
							Message:   "There are 2 duplicate HEALTHCHECK instructions in the stage 'busybox:1.33.1'",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS023",
								Type:     "Dockerfile Security Check",
								Title:    "Multiple HEALTHCHECK are defined",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		{
			name:  "DS024: Do not use apt-get dist-upgrade",
			input: "testdata/DS024",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS024",
							Message:   "'apt-get dist-upgrade' should not be used in Dockerfile",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS024",
								Type:     "Dockerfile Security Check",
								Title:    "'apt-get dist-upgrade' is used",
								Severity: "HIGH",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Initialize local cache
			cacheClient, err := cache.NewFSCache(tmpDir)
			require.NoError(t, err)

			art, err := local.NewArtifact(tt.input, cacheClient, nil, config.ScannerOption{
				Namespaces:  []string{"appshield"},
				PolicyPaths: []string{"../docker"},
			})
			require.NoError(t, err)

			// Scan config files
			result, err := art.Inspect(context.Background())
			require.NoError(t, err)

			// Merge layers
			a := applier.NewApplier(cacheClient)
			mergedLayer, err := a.ApplyLayers(result.ID, result.BlobIDs)
			if !errors.Is(err, analyzer.ErrUnknownOS) && !errors.Is(err, analyzer.ErrNoPkgsDetected) {
				require.NoError(t, err)
			}

			// Do not assert successes and layer
			for i := range mergedLayer.Misconfigurations {
				mergedLayer.Misconfigurations[i].Successes = nil
				mergedLayer.Misconfigurations[i].Layer = types.Layer{}
			}

			// For consistency
			sort.Slice(mergedLayer.Misconfigurations, func(i, j int) bool {
				return mergedLayer.Misconfigurations[i].FilePath < mergedLayer.Misconfigurations[j].FilePath
			})

			// Assert the scan result
			assert.Equal(t, tt.want, mergedLayer.Misconfigurations)
		})
	}
}
