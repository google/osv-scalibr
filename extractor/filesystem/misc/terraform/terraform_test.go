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

package terraform_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/terraform"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "terraform file",
			path:         "main.tf",
			wantRequired: true,
		},
		{
			name:         "terraform file with path",
			path:         "/path/to/main.tf",
			wantRequired: true,
		},
		{
			name:         "not terraform file",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "txt file",
			path:         "readme.txt",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = terraform.Extractor{}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: 30 * 1024,
			})); got != tt.wantRequired {
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
			name: "module with version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/terraform-1.tf",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "terraform-aws-modules/vpc/aws",
					Version:   "6.0.1",
					PURLType:  purl.TypeTerraform,
					Locations: []string{"testdata/terraform-1.tf"},
				},
			},
		},
		{
			name: "local module without version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/terraform-2.tf",
			},
			wantPackages: nil,
		},
		{
			name: "provider with version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/terraform-3.tf",
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "hashicorp/aws",
					Version:   "~> 5.92",
					PURLType:  purl.TypeTerraform,
					Locations: []string{"testdata/terraform-3.tf"},
				},
			},
		},
		{
			name: "provider without version",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/terraform-4.tf",
			},
			wantPackages: nil,
		},
		{
			name: "empty terraform file",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.tf",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := terraform.Extractor{}

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
	tests := []struct {
		name            string
		inputConfigFile extracttest.ScanInputMockConfig
		wantErr         bool
	}{
		{
			name: "invalid terraform file",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.tf",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := terraform.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			_, err := extr.Extract(t.Context(), &scanInput)
			if (err != nil) != tt.wantErr {
				t.Errorf("Extract() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
