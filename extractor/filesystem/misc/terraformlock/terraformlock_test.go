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

package terraformlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/terraformlock"
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
			name:         "valid .terraform.lock.hcl",
			path:         "testdata/.terraform.lock.hcl",
			wantRequired: true,
		},
		{
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "wrong filename",
			path:         "testdata/terraform.lock.hcl",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = terraformlock.Extractor{}
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
			name: "valid .terraform.lock.hcl",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/.terraform.lock.hcl",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "registry.terraform.io/hashicorp/aws",
					Version:   "5.100.0",
					PURLType:  purl.TypeTerraform,
					Locations: []string{"testdata/.terraform.lock.hcl"},
				},
			},
		},
		{
			name: "empty .terraform.lock.hcl",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.terraform.lock.hcl",
			},
			wantPackages: nil,
		},
		{
			name: "no version .terraform.lock.hcl",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/no-version.terraform.lock.hcl",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := terraformlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}

func TestExtractErrors(t *testing.T) {
	extr := terraformlock.Extractor{}

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/invalid.terraform.lock.hcl",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	_, err := extr.Extract(t.Context(), &scanInput)
	if err == nil {
		t.Errorf("expected Error from Extract() but got = %v", err)
	}
}
