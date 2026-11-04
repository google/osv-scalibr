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

package yarnpnp_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnpnp"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty_path",
			path: "",
		},
		{
			name: "pnp_cjs",
			path: ".pnp.cjs",
			want: true,
		},
		{
			name: "nested_pnp_cjs",
			path: filepath.FromSlash("path/to/project/.pnp.cjs"),
			want: true,
		},
		{
			name: "pnp_data_json",
			path: ".pnp.data.json",
			want: true,
		},
		{
			name: "pnp_js",
			path: ".pnp.js",
		},
		{
			name: "wrong_suffix",
			path: ".pnp.cjs.backup",
		},
		{
			name: "inside_node_modules",
			path: filepath.FromSlash("foo/node_modules/bar/.pnp.cjs"),
		},
	}

	extr, err := yarnpnp.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("yarnpnp.New: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extr.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "pnp_data_json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/.pnp.data.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/.pnp.data.json"),
				},
				{
					Name:     "@scope/pkg",
					Version:  "1.2.3-beta.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/.pnp.data.json"),
				},
				{
					Name:     "typescript",
					Version:  "5.9.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/.pnp.data.json"),
				},
			},
		},
		{
			Name: "yarn_3_inline_cjs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/yarn3/.pnp.cjs",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "is-number",
					Version:  "7.0.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/yarn3/.pnp.cjs"),
				},
			},
		},
		{
			Name: "yarn_4_inline_cjs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/yarn4/.pnp.cjs",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "left-pad",
					Version:  "1.3.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/yarn4/.pnp.cjs"),
				},
			},
		},
		{
			Name: "external_data_cjs",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/external/.pnp.cjs",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid_json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/.pnp.data.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "parsing Plug'n'Play data"},
		},
		{
			Name: "missing_package_registry",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-registry/.pnp.data.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "missing packageRegistryData"},
		},
		{
			Name: "malformed_registry_entry",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed-registry/.pnp.data.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid package registry entry"},
		},
		{
			Name: "unterminated_inline_data",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/unterminated/.pnp.cjs",
			},
			WantErr: extracttest.ContainsErrStr{Str: "unterminated JavaScript string"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := yarnpnp.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("yarnpnp.New: %v", err)
			}
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			want := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
