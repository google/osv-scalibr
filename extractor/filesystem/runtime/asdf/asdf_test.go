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

package asdf_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/asdf/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "invalid_path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "tool_versions_at_root",
			path:         ".tool-versions",
			wantRequired: true,
		},
		{
			name:         "nested_tool_versions",
			path:         "/tmp/project/.tool-versions",
			wantRequired: true,
		},
		{
			name:         "backup_tool_versions_not_required",
			path:         "/tmp/project/.tool-versions.bak",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := asdf.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
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
			name: "valid_.tool-versions_",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/simpleValid/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Location: extractor.LocationFromPath("testdata/simpleValid/.tool-versions"),
				},
			},
		}, {
			name: "valid_.tool-versions_multiple_versions",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiVersions/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersions/.tool-versions"),
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersions/.tool-versions"),
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersions/.tool-versions"),
				},
			},
		}, {
			name: "valid_.tool-versions_multiple_versions_with_skip_values",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiVersionWithSkip/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersionWithSkip/.tool-versions"),
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersionWithSkip/.tool-versions"),
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Location: extractor.LocationFromPath("testdata/validMultiVersionWithSkip/.tool-versions"),
				},
			},
		}, {
			name: "valid_.tool-versions_multiple_lines",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validMultiLine/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Location: extractor.LocationFromPath("testdata/validMultiLine/.tool-versions"),
				}, {
					Name:     "nodejs",
					Version:  "20.0",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "20.0",
					},
					Location: extractor.LocationFromPath("testdata/validMultiLine/.tool-versions"),
				},
			},
		}, {
			name: "valid_.tool-versions_more_whitespaces",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validWhiteSpaces/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Location: extractor.LocationFromPath("testdata/validWhiteSpaces/.tool-versions"),
				},
			},
		},
		{
			name: "aliases_v_prefix_inline_comments_and_skip_specifiers",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/validAliasesAndSkips/.tool-versions",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "20.12.2",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "node",
						ToolVersion: "v20.12.2",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "golang",
					Version:  "1.21.9",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "go",
						ToolVersion: "1.21.9",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "golang",
					Version:  "1.22.4",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "core:go",
						ToolVersion: "1.22.4",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "cmake",
					Version:  "3.29.6",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "vfox:cmake",
						ToolVersion: "3.29.6",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "java",
					Version:  "temurin-21.0.2+13.0.LTS",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "java",
						ToolVersion: "temurin-21.0.2+13.0.LTS",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "python",
					Version:  "3.12.1",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "py",
						ToolVersion: "3.12.1",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
				{
					Name:     "terraform",
					Version:  "1.6.0",
					PURLType: purl.TypeGeneric,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "terraform",
						ToolVersion: "1.6.0",
					},
					Location: extractor.LocationFromPath("testdata/validAliasesAndSkips/.tool-versions"),
				},
			},
		},
		{
			name: "invalid_.tool-versions_",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/.tool-versions",
			},
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := asdf.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("%s.Extract(%q) error = %v", extr.Name(), tt.inputConfigFile.Path, err)
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
