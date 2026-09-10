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

package gleamtoml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/gleam/gleamtoml"
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
			name:      "gleam_toml",
			inputPath: "gleam.toml",
			want:      true,
		},
		{
			name:      "path_to_gleam_toml",
			inputPath: "path/to/gleam.toml",
			want:      true,
		},
		{
			name:      "not_gleam_toml",
			inputPath: "not-gleam.toml",
			want:      false,
		},
		{
			name:      "gleam_toml_bak",
			inputPath: "gleam.toml.bak",
			want:      false,
		},
		{
			name:      "Cargo_toml",
			inputPath: "Cargo.toml",
			want:      false,
		},
		{
			name:      "empty_path",
			inputPath: "",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gleamtoml.Extractor{}
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
			Name: "invalid_toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "no_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-deps.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "only_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gleam_stdlib",
					Version:  ">= 0.34.0 and < 2.0.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/only-deps.toml"),
				},
			},
		},
		{
			Name: "only_dev_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-dev-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gleeunit",
					Version:  ">= 1.0.0 and < 2.0.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/only-dev-deps.toml"),
				},
			},
		},
		{
			Name: "git_and_local_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-and-local-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gleam_stdlib",
					Version:  ">= 0.34.0 and < 2.0.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/git-and-local-deps.toml"),
				},
				{
					Name:     "my_git_package",
					Version:  "",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/git-and-local-deps.toml"),
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/my-username/my_git_package",
						Commit: "a8b3c5d82",
					},
				},
				// my_local_package is skipped
			},
		},
		{
			Name: "deps_and_dev_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/deps-and-dev-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "gleam_stdlib",
					Version:  ">= 0.34.0 and < 2.0.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/deps-and-dev-deps.toml"),
				},
				{
					Name:     "gleeunit",
					Version:  ">= 1.0.0 and < 2.0.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPath("testdata/deps-and-dev-deps.toml"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gleamtoml.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
