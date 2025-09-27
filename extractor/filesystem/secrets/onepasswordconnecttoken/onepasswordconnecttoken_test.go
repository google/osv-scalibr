// Copyright 2025 Google LLC
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

package onepasswordconnecttoken_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/onepasswordconnecttoken"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/onepasswordconnecttoken/metadata"
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
			name:         "valid onepassword json file",
			path:         "/project/onepassword-token.json",
			wantRequired: true,
		},
		{
			name:         "valid 1password json file",
			path:         "/project/1password-config.json",
			wantRequired: true,
		},
		{
			name:         "onepassword uppercase",
			path:         "/project/ONEPASSWORD-settings.json",
			wantRequired: true,
		},
		{
			name:         "invalid extension",
			path:         "/project/onepassword-token.txt",
			wantRequired: false,
		},
		{
			name:         "no onepassword in name",
			path:         "/project/config.json",
			wantRequired: false,
		},
		{
			name:         "not json file",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = onepasswordconnecttoken.Extractor{}
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
			name: "valid onepassword connect token",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/valid-onepassword-token.json",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "onepassword-connect-token",
					Version:  "2",
					PURLType: purl.TypeGeneric,
					Metadata: &metadata.Metadata{
						DeviceUUID: "yrkdmusoblmgm6siuj4kcssxke",
						Version:    "2",
					},
					Locations: []string{"testdata/valid-onepassword-token.json"},
				},
			},
		},
		{
			name: "invalid json",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.json",
			},
			wantPackages: nil,
		},
		{
			name: "missing required fields",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/incomplete.json",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := onepasswordconnecttoken.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if tt.wantPackages == nil && err == nil {
				// For invalid cases, we expect empty inventory
				wantInv := inventory.Inventory{}
				if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
					t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
				}
				return
			}

			if err != nil && tt.wantPackages != nil {
				t.Fatalf("Extract() error = %v, want nil", err)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
