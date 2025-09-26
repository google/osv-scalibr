package bazelmaven

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	bazelmavenmeta "github.com/google/osv-scalibr/extractor/filesystem/misc/bazelmaven/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		wantPackages    []*extractor.Package
		wantErrContains string
		inputConfigFile extracttest.ScanInputMockConfig
	}{
		{
			name: "basic maven_install",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/MODULE.bazel",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "group1:artifact1:1",
					Version:  "1",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group1:artifact1:1",
						GroupID:    "group1",
						ArtifactID: "artifact1",
						Version:    "1",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group2:artifact2:2",
					Version:  "2",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group2:artifact2:2",
						GroupID:    "group2",
						ArtifactID: "artifact2",
						Version:    "2",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group3:artifact3:3",
					Version:  "3",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group3:artifact3:3",
						GroupID:    "group3",
						ArtifactID: "artifact3",
						Version:    "3",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group4:artifact4:4",
					Version:  "4",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group4:artifact4:4",
						GroupID:    "group4",
						ArtifactID: "artifact4",
						Version:    "4",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group5:artifact5:5",
					Version:  "5",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group5:artifact5:5",
						GroupID:    "group5",
						ArtifactID: "artifact5",
						Version:    "5",
						RuleName:   "maven.artifact",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group6:artifact6:6",
					Version:  "6",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group6:artifact6:6",
						GroupID:    "group6",
						ArtifactID: "artifact6",
						Version:    "6",
						RuleName:   "maven_install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group7:artifact7:7",
					Version:  "7",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group7:artifact7:7",
						GroupID:    "group7",
						ArtifactID: "artifact7",
						Version:    "7",
						RuleName:   "maven_install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
			},
		},
		{
			name: "empty build file",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/EMPTY.bazel",
			},
			wantPackages: nil,
		},
		{
			name: "invalid build file",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/INVALID.bazel",
			},
			wantPackages:    nil,
			wantErrContains: "failed to parse Bazel file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			// Check for error expectations
			gotErr := ""
			if err != nil {
				gotErr = err.Error()
			}

			// Error case: we expect an error
			if tt.wantErrContains != "" {
				if gotErr == "" {
					t.Errorf("%s.Extract(%q) expected error containing %q, got nil",
						extr.Name(), tt.inputConfigFile.Path, tt.wantErrContains)
					return
				}

				if !strings.Contains(gotErr, tt.wantErrContains) {
					diff := cmp.Diff(tt.wantErrContains, gotErr,
						cmpopts.AcyclicTransformer("ErrSubstr", func(s string) string {
							return fmt.Sprintf("Error should contain: %q", s)
						}))
					t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s",
						extr.Name(), tt.inputConfigFile.Path, diff)
				}
				return
			}

			// No error case: we don't expect an error but got one
			if err != nil {
				diff := cmp.Diff("no error", gotErr)
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s",
					extr.Name(), tt.inputConfigFile.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
