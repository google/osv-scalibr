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

package cargotoml_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargotoml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "Empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "Cargo.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/Cargo.toml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.Cargo.toml",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := cargotoml.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "Invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "Invalid dependency toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-dependency.toml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/no-dependency.toml"},
				},
			},
		},
		{
			Name: "dependency with only version specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-version-dependency.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/only-version-dependency.toml"},
				},
				{
					Name:      "regex",
					Version:   "0.0.1",
					Locations: []string{"testdata/only-version-dependency.toml"},
				},
			},
		},
		{
			// dependencies with only tag specified should be skipped
			Name: "git dependency with tag specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-tagged.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/git-dependency-tagged.toml"},
				},
			},
		},
		{
			Name: "git dependency with commit specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-with-commit.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/git-dependency-with-commit.toml"},
				},
				{
					Name: "regex",
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/rust-lang/regex.git",
						Commit: "0c0990399270277832fbb5b91a1fa118e6f63dba",
					},
					Locations: []string{"testdata/git-dependency-with-commit.toml"},
				},
			},
		},
		{
			Name: "git dependency with pr rev specified",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency-with-pr.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/git-dependency-with-pr.toml"},
				},
			},
		},
		{
			Name: "two dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-dependencies.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "hello_world",
					Version:   "0.1.0",
					Locations: []string{"testdata/two-dependencies.toml"},
				},
				{
					Name:      "futures",
					Version:   "0.3",
					Locations: []string{"testdata/two-dependencies.toml"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := cargotoml.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

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
