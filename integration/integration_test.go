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
