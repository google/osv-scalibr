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

package manifesttoml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/julia/manifesttoml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "Manifest.toml file",
			inputPath: "Manifest.toml",
			want:      true,
		},
		{
			name:      "path with Manifest.toml",
			inputPath: "path/to/Manifest.toml",
			want:      true,
		},
		{
			name:      "Cargo.toml file",
			inputPath: "Cargo.toml",
			want:      false,
		},
		{
			name:      "manifest.toml (lowercase)",
			inputPath: "manifest.toml",
			want:      false,
		},
		{
			name:      "Project.toml file",
			inputPath: "Project.toml",
			want:      false,
		},
		{
			name:      "Manifest.toml.backup",
			inputPath: "Manifest.toml.backup",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := manifesttoml.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-dependency.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "only version dependency - JSON package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-version-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "JSON",
					Version:   "0.20.0",
					PURLType:  purl.TypeJulia,
					Locations: []string{"testdata/only-version-dependency.toml"},
				},
			},
		},
		{
			Name: "git dependency with both packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-with-commit.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "DataStructures",
					Version:   "0.17.0",
					PURLType:  purl.TypeJulia,
					Locations: []string{"testdata/git-dependency-with-commit.toml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0809951a1774dc724da22d26e4289bbaab77809a",
					},
				},
				{
					Name:      "Unregistered",
					Version:   "0.2.0",
					PURLType:  purl.TypeJulia,
					Locations: []string{"testdata/git-dependency-with-commit.toml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/00vareladavid/Unregistered.jl",
						Commit: "cca953732cd949cfe36d70e981a41ac32a5c6ae7",
					},
				},
			},
		},
		{
			Name: "no version dependency - should be filtered out",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-version-dependency.toml",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := manifesttoml.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
