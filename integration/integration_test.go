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
							Namespace: "appshield.DS002",
							Message:   "Specify at least 1 USER command in Dockerfile",
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
			name:  "DS003: apt cache",
			input: "testdata/DS003",
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
							Namespace: "appshield.DS003",
							Message:   "Clean apt cache",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS003",
								Type:     "Dockerfile Security Check",
								Title:    "Clean APT cache",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		/*there is separate issue with DS004
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
							Namespace: "appshield.DS004",
							Message:   "Specify Port to SSH into the container",
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS004",
								Type:     "Dockerfile Security Check",
								Title:    "Exposing Port 22",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},*/

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
							Namespace: "appshield.DS005",
							Message:   `expected COPY "/target/app.jar" "app.jar" instead of ADD "/target/app.jar" "app.jar"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS005",
								Type:     "Dockerfile Security Check",
								Title:    "COPY Instead of ADD",
								Severity: "MEDIUM",
							},
						},
					},
				},
			},
		},
		/*there is separate issue with DS006
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
							Namespace: "appshield.DS006",
							Message:   `expected COPY "/target/app.jar" "app.jar" instead of ADD "/target/app.jar" "app.jar"`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS006",
								Type:     "Dockerfile Security Check",
								Title:    "COPY '--from' references current image FROM alias",
								Severity: "CRITICAL",
							},
						},
					},
				},
			},
		},*/
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
							Namespace: "appshield.DS007",
							Message:   `There are 2 duplicate ENTRYPOINT instructions`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS007",
								Type:     "Dockerfile Security Check",
								Title:    "Multiple ENTRYPOINT Instructions Listed",
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
							Namespace: "appshield.DS008",
							Message:   `'EXPOSE' contains port which is out of range [0, 65535]: 65536`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS008",
								Type:     "Dockerfile Security Check",
								Title:    "UNIX Ports Out Of Range",
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
							Namespace: "appshield.DS009",
							Message:   `Path path/to/workdir isn't absolute`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS009",
								Type:     "Dockerfile Security Check",
								Title:    "WORKDIR Path Not Absolute",
								Severity: "CRITICAL",
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
							Namespace: "appshield.DS010",
							Message:   `Shouldn't use sudo in Dockerfile`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS010",
								Type:     "Dockerfile Security Check",
								Title:    "Run Using Sudo",
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
							Namespace: "appshield.DS011",
							Message:   `Slash is expected at the end of myapp`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS011",
								Type:     "Dockerfile Security Check",
								Title:    "Copy With More Than Two Arguments Not Ending With Slash",
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
							Namespace: "appshield.DS012",
							Message:   `Duplicate alias found among: [debian:jesse1 as build, debian:jesse2 as build]`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS012",
								Type:     "Dockerfile Security Check",
								Title:    "Same Alias In Different Froms",
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
							Namespace: "appshield.DS013",
							Message:   `RUN shouldn't be used to change directory: 'cd /usr/share/nginx/html'`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS013",
								Type:     "Dockerfile Security Check",
								Title:    "RUN Instruction Using 'cd' Instead of WORKDIR",
								Severity: "HIGH",
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
							Namespace: "appshield.DS014",
							Message:   `Shouldn't use both curl and wget`,
							PolicyMetadata: types.PolicyMetadata{
								ID:       "DS014",
								Type:     "Dockerfile Security Check",
								Title:    "Run Using 'wget' and 'curl'",
								Severity: "HIGH",
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
							Namespace: "appshield.DS015",
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

			for _, m := range mergedLayer.Misconfigurations {
				t.Logf("Filetype: %v\n", m.FileType)
				t.Logf("Filename: %s\n", m.FilePath)
				t.Logf("Failures:\n")

				if len(m.Failures) == 0 {
					t.Logf("	No failures!\n")
				}

				for _, f := range m.Failures {
					t.Logf("	Namespace: %s\n", f.Namespace)
					t.Logf("	Message: %s\n", f.Message)
				}
			}
			// Assert the scan result
			assert.Equal(t, tt.want, mergedLayer.Misconfigurations)
		})
	}
}
