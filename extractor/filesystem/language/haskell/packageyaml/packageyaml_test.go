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

package packageyaml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/packageyaml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "package.yaml",
			inputPath: "package.yaml",
			want:      true,
		},
		{
			name:      "path/to/package.yaml",
			inputPath: "path/to/my/package.yaml",
			want:      true,
		},
		{
			name:      "package.yaml/file",
			inputPath: "path/to/my/package.yaml/file",
			want:      false,
		},
		{
			name:      "package.yml",
			inputPath: "path/to/my/package.yml",
			want:      false,
		},
		{
			name:      "not package.yaml",
			inputPath: "path/to/my/package.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := packageyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packageyaml.New: %v", err)
			}
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
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-yaml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "yaml.Unmarshal"},
			WantPackages: nil,
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-deps.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty list",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-list.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty map",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-map.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-dep.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					Version:  "",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/one-dep.yaml"),
				},
			},
		},
		{
			Name: "list dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/list-deps.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					Version:  ">= 4.14 && < 5",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/list-deps.yaml"),
				},
				{
					Name:     "aeson",
					Version:  ">= 2.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/list-deps.yaml"),
				},
				{
					Name:     "bytestring",
					Version:  "",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/list-deps.yaml"),
				},
			},
		},
		{
			Name: "map dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/map-deps.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					Version:  ">= 4.14 && < 5",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/map-deps.yaml"),
				},
				{
					Name:     "aeson",
					Version:  ">= 2.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/map-deps.yaml"),
				},
				{
					Name:     "bytestring",
					Version:  "",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/map-deps.yaml"),
				},
			},
		},
		{
			Name: "component dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/component-deps.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					Version:  ">= 4.14 && < 5",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/component-deps.yaml"),
				},
				{
					Name:     "text",
					Version:  ">= 2.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/component-deps.yaml"),
				},
				{
					Name:     "aeson",
					Version:  ">= 2.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/component-deps.yaml"),
				},
				{
					Name:     "hspec",
					Version:  ">= 2.10",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/component-deps.yaml"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := packageyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packageyaml.New: %v", err)
			}

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
