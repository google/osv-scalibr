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
			name:      "empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "exact package_config.json not in dart_tool",
			inputPath: "package_config.json",
			want:      false,
		},
		{
			name:      "dart_tool package_config.json",
			inputPath: ".dart_tool/package_config.json",
			want:      true,
		},
		{
			name:      "nested dart_tool package_config.json",
			inputPath: "path/to/project/.dart_tool/package_config.json",
			want:      true,
		},
		{
			name:      "package_config.json in unrelated dir",
			inputPath: "mypkg/package_config.json",
			want:      false,
		},
		{
			name:      "package_config.json-like file",
			inputPath: ".dart_tool/package_config.json.bak",
			want:      false,
		},
		{
			name:      "directory named package_config.json",
			inputPath: ".dart_tool/package_config.json/file",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := packageconfig.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("packageconfig.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "malformed json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.json",
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
			Name: "basic config without versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "shelf",
					Version:  "",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/basic.json"),
				},
				{
					Name:     "shelf_web_socket",
					Version:  "",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/basic.json"),
				},
			},
		},
		{
			Name: "config with versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-versions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "http",
					Version:  "1.1.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/with-versions.json"),
				},
				{
					Name:     "path",
					Version:  "1.8.3",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/with-versions.json"),
				},
			},
		},
		{
			Name: "missing and empty versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-versions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "no_version_pkg",
					Version:  "",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/missing-versions.json"),
				},
				{
					Name:     "empty_version_pkg",
					Version:  "",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/missing-versions.json"),
				},
				{
					Name:     "with_version_pkg",
					Version:  "0.4.1",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/missing-versions.json"),
				},
			},
		},
		{
			Name: "missing and blank names are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-names.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "good_pkg",
					Version:  "1.0.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/missing-names.json"),
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
