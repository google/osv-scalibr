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

package mise_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/runtime/mise"
	misemeta "github.com/google/osv-scalibr/extractor/filesystem/runtime/mise/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
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
			name:         "invalid_path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "mise_toml",
			path:         "mise.toml",
			wantRequired: true,
		},
		{
			name:         "nested_mise_toml",
			path:         "/tmp/project/mise.toml",
			wantRequired: true,
		},
		{
			name:         "mise_local_toml",
			path:         "/tmp/project/mise.local.toml",
			wantRequired: true,
		},
		{
			name:         "config_mise_toml",
			path:         "/home/user/.config/mise.toml",
			wantRequired: true,
		},
		{
			name:         "mise_dir_config_toml",
			path:         "/tmp/project/mise/config.toml",
			wantRequired: true,
		},
		{
			name:         "dot_mise_config_toml",
			path:         "/tmp/project/.mise/config.toml",
			wantRequired: true,
		},
		{
			name:         "config_mise_dir_config_toml",
			path:         "/home/user/.config/mise/config.toml",
			wantRequired: true,
		},
		{
			name:         "config_mise_conf_d_toml",
			path:         "/home/user/.config/mise/conf.d/tools.toml",
			wantRequired: true,
		},
		{
			name:         "unrelated_config_toml",
			path:         "/tmp/project/config.toml",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := mise.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid_mise_toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid-mise.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "aws-cli",
					Version:  "2",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "aws-cli",
						ToolVersion: "2",
					},
					Location: extractor.LocationFromPath("testdata/valid-mise.toml"),
				},
				{
					Name:     "nodejs",
					Version:  "22",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "node",
						ToolVersion: "22",
					},
					Location: extractor.LocationFromPath("testdata/valid-mise.toml"),
				},
				{
					Name:     "terraform",
					Version:  "1",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "terraform",
						ToolVersion: "1",
					},
					Location: extractor.LocationFromPath("testdata/valid-mise.toml"),
				},
			},
		},
		{
			Name: "aliases_prefixes_arrays_and_skips",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/aliases-arrays-skips.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "golang",
					Version:  "1.22.4",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "CORE:go",
						ToolVersion: "v1.22.4",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "nodejs",
					Version:  "20.12.2",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "Node",
						ToolVersion: "v20.12.2",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "runc",
					Version:  "1.1.12",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "asdf:runc",
						ToolVersion: "1.1.12",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "bun",
					Version:  "1.1.0",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "bun",
						ToolVersion: "1.1.0",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "custom",
					Version:  "ver-1.0.0",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "custom",
						ToolVersion: "ver-1.0.0",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "java",
					Version:  "temurin-21.0.2+13.0.LTS",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "java",
						ToolVersion: "temurin-21.0.2+13.0.LTS",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "python",
					Version:  "3.12.1",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "py",
						ToolVersion: "3.12.1",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "python",
					Version:  "3.11.9",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "py",
						ToolVersion: "3.11.9",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
				{
					Name:     "cmake",
					Version:  "3.29.6",
					PURLType: purl.TypeGeneric,
					Metadata: &misemeta.Metadata{
						ToolName:    "vfox:cmake",
						ToolVersion: "3.29.6",
					},
					Location: extractor.LocationFromPath("testdata/aliases-arrays-skips.toml"),
				},
			},
		},
		{
			Name: "empty_mise_toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-mise.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid_toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-valid-toml.toml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := mise.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
