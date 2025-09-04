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

package asdf_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/asdf"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/language/asdf/metadata"
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
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = asdf.Extractor{}
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
			name: "valid .tool-versions ",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/simpleValid/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"testdata/simpleValid/.tool-versions"},
				},
			},
		}, {
			name: "valid .tool-versions multiple versions",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiVersions/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"testdata/validMultiVersions/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Locations: []string{"testdata/validMultiVersions/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Locations: []string{"testdata/validMultiVersions/.tool-versions"},
				},
			},
		}, {
			name: "valid .tool-versions multiple versions with skip values",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiVersionWithSkip/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"testdata/validMultiVersionWithSkip/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Locations: []string{"testdata/validMultiVersionWithSkip/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Locations: []string{"testdata/validMultiVersionWithSkip/.tool-versions"},
				},
			},
		}, {
			name: "valid .tool-versions multiple lines",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiLine/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"testdata/validMultiLine/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "20.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "20.0",
					},
					Locations: []string{"testdata/validMultiLine/.tool-versions"},
				},
			},
		}, {
			name: "valid .tool-versions more whitespaces",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validWhiteSpaces/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"testdata/validWhiteSpaces/.tool-versions"},
				},
			},
		},
		{
			name: "invalid .tool-versions ",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/.tool-versions",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := asdf.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, _ := extr.Extract(t.Context(), &scanInput)

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
