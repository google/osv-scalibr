// Copyright 2024 Google LLC
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

package packageconfig_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/packageconfig"
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
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "package_config.json",
			want:      true,
		},
		{
			inputPath: ".dart_tool/package_config.json",
			want:      true,
		},
		{
			inputPath: "path/to/my/package_config.json",
			want:      true,
		},
		{
			inputPath: "path/to/my/package_config.json/file",
			want:      false,
		},
		{
			inputPath: "package_config.yaml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := packageconfig.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packageconfig.New() error: %v", err)
			}
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
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "v2 packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package_config.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "async",
					Version:   "2.11.0",
					PURLType:  purl.TypePub,
					Locations: []string{"testdata/package_config.json"},
				},
				{
					Name:      "boolean_selector",
					Version:   "2.1.1",
					PURLType:  purl.TypePub,
					Locations: []string{"testdata/package_config.json"},
				},
				{
					Name:      "my_local_package",
					Version:   "",
					PURLType:  purl.TypePub,
					Locations: []string{"testdata/package_config.json"},
				},
			},
		},
		{
			Name: "v1 packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/package_config_v1.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "async",
					Version:   "2.11.0",
					PURLType:  purl.TypePub,
					Locations: []string{"testdata/package_config_v1.json"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := packageconfig.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packageconfig.New() error: %v", err)
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

