package bazelmaven

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	bazelmavenmeta "github.com/google/osv-scalibr/extractor/filesystem/os/bazelmaven/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		wantPackages    []*extractor.Package
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
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group1:artifact1:1",
						GroupID:    "group1",
						ArtifactID: "artifact1",
						Version:    "1",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group2:artifact2:2",
					Version:  "2",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group2:artifact2:2",
						GroupID:    "group2",
						ArtifactID: "artifact2",
						Version:    "2",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group3:artifact3:3",
					Version:  "3",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group3:artifact3:3",
						GroupID:    "group3",
						ArtifactID: "artifact3",
						Version:    "3",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group4:artifact4:4",
					Version:  "4",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group4:artifact4:4",
						GroupID:    "group4",
						ArtifactID: "artifact4",
						Version:    "4",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group5:artifact5:5",
					Version:  "5",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group5:artifact5:5",
						GroupID:    "group5",
						ArtifactID: "artifact5",
						Version:    "5",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group6:artifact6:6",
					Version:  "6",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group6:artifact6:6",
						GroupID:    "group6",
						ArtifactID: "artifact6",
						Version:    "6",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group7:artifact7:7",
					Version:  "7",
					PURLType: purl.TypeBazelMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group7:artifact7:7",
						GroupID:    "group7",
						ArtifactID: "artifact7",
						Version:    "7",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, _ := extr.Extract(t.Context(), &scanInput)

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
