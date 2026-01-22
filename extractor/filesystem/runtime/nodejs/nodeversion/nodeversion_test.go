// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nodeversion_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nodeversion"
	"github.com/google/osv-scalibr/extractor/filesystem/runtime/nodejs/nodeversion/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid .node-version file",
			path:         "/project/.node-version",
			wantRequired: true,
		},
		{
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "not node-version file",
			path:         "/project/package.json",
			wantRequired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = nodeversion.Extractor{}
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		wantPackages    []*extractor.Package
		inputConfigFile extracttest.ScanInputMockConfig
	}{
		{
			name: "valid_.node-version_with_version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/simpleValidWithComments.node-version",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "20.1.0",
					PURLType: purl.TypeGeneric,
					Metadata: &metadata.Metadata{
						NodeJsVersion: "20.1.0",
					},
					Locations: []string{"testdata/simpleValidWithComments.node-version"},
				},
			},
		},
		{
			name: "valid_.node-version_with_whitespaces_and_comments",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validWhiteSpaces.node-version",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &metadata.Metadata{
						NodeJsVersion: "24.04",
					},
					Locations: []string{"testdata/validWhiteSpaces.node-version"},
				},
			},
		},
		{
			name: ".node-version_with_node_and_lts_instead_of_version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/notNumericVersion.node-version",
			},
			wantPackages: nil,
		},
		{
			name: ".node-version_with_no_numerical_version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiVersionWithSkip.node-version",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := nodeversion.Extractor{}

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
