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

package electronasar_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/electronasar"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "app.asar_in_resources",
			path:         "opt/myapp/resources/app.asar",
			wantRequired: true,
		},
		{
			name:         "app.asar_nested_resources",
			path:         "Applications/MyApp.app/Contents/Resources/app.asar",
			wantRequired: true,
		},
		{
			name:         "wrong_filename",
			path:         "opt/myapp/resources/other.asar",
			wantRequired: false,
		},
		{
			name:         "no_resources_dir",
			path:         "opt/myapp/app.asar",
			wantRequired: false,
		},
		{
			name:         "not_asar",
			path:         "opt/myapp/resources/app.zip",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := electronasar.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.wantRequired {
				t.Errorf("FileRequired(%q) = %v, want %v",
					tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "two_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/app.asar",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/app.asar"),
				},
				{
					Name:     "semver",
					Version:  "7.5.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/app.asar"),
				},
			},
		},
		{
			Name: "no_node_modules",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_node_modules.asar",
			},
			WantPackages: nil,
		},
		{
			Name: "scoped_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped_packages.asar",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "lodash",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/scoped_packages.asar"),
				},
				{
					Name:     "@types/node",
					Version:  "18.15.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/scoped_packages.asar"),
				},
				{
					Name:     "@babel/core",
					Version:  "7.21.3",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/scoped_packages.asar"),
				},
			},
		},
		{
			// npm installs a conflicting dependency version inside the
			// dependent package's own node_modules directory. Both the
			// top-level version (undici-types@8.7.0) and the nested
			// conflict-resolution version (undici-types@8.3.0 inside
			// @types/node) must be reported.
			Name: "nested_node_modules",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested_node_modules.asar",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@types/node",
					Version:  "26.1.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/nested_node_modules.asar"),
				},
				{
					// Nested conflict-resolution copy inside @types/node.
					Name:     "undici-types",
					Version:  "8.3.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/nested_node_modules.asar"),
				},
				{
					// Top-level hoisted copy.
					Name:     "undici-types",
					Version:  "8.7.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/nested_node_modules.asar"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := electronasar.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New(): %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(context.Background(), &scanInput)

			if diff := cmp.Diff(
				tt.WantErr, err,
				cmpopts.EquateErrors(),
			); diff != "" {
				t.Errorf("Extract() error mismatch (-want +got):\n%s", diff)
			}

			wantInv := tt.WantPackages
			gotInv := got.Packages
			if diff := cmp.Diff(
				wantInv, gotInv,
				cmpopts.SortSlices(extracttest.PackageCmpLess),
				cmpopts.EquateEmpty(),
			); diff != "" {
				t.Errorf("Extract() packages mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
