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

package pixitoml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pixitoml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "pixi_toml",
			inputPath: "pixi.toml",
			want:      true,
		},
		{
			name:      "path_to_pixi_toml",
			inputPath: "path/to/pixi.toml",
			want:      true,
		},
		{
			name:      "not_pixi_toml",
			inputPath: "not-pixi.toml",
			want:      false,
		},
		{
			name:      "pixi_toml_bak",
			inputPath: "pixi.toml.bak",
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
			e := pixitoml.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
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
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "valid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "flask",
					Version:  "*",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "numpy",
					Version:  ">=1.24",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "python",
					Version:  ">=3.9",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "pytest",
					Version:  ">=8",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "openssl",
					Version:  ">=3",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "pyobjc",
					Version:  ">=10",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "requests",
					Version:  ">=2.26.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
				{
					Name:     "sphinx",
					Version:  ">=7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
				},
			},
		},
		{
			Name: "only_conda",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-conda.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "numpy",
					Version:  ">=1.24",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/only-conda.toml"),
				},
				{
					Name:     "python",
					Version:  ">=3.9",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/only-conda.toml"),
				},
			},
		},
		{
			Name: "only_pypi",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-pypi.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "flask",
					Version:  "*",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/only-pypi.toml"),
				},
				{
					Name:     "requests",
					Version:  ">=2.26.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/only-pypi.toml"),
				},
			},
		},
		{
			Name: "table_dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/table-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "numpy",
					Version:  ">=1.24",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/table-deps.toml"),
				},
				{
					Name:     "python",
					Version:  ">=3.9",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPath("testdata/table-deps.toml"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pixitoml.Extractor{}

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
