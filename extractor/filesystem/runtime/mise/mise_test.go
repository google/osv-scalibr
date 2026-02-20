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
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
		{
			name:         "mise.toml",
			path:         "mise.toml",
			wantRequired: true,
		},
		{
			name:         "nested mise.toml",
			path:         "/tmp/project/mise.toml",
			wantRequired: true,
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
			Name: "valid mise.toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid-mise.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "terraform",
					Version:  "1",
					PURLType: purl.TypeMise,
					Metadata: &misemeta.Metadata{
						ToolName:    "terraform",
						ToolVersion: "1",
					},
					Locations: []string{"testdata/valid-mise.toml"},
				},
				{
					Name:     "aws-cli",
					Version:  "2",
					PURLType: purl.TypeMise,
					Metadata: &misemeta.Metadata{
						ToolName:    "aws-cli",
						ToolVersion: "2",
					},
					Locations: []string{"testdata/valid-mise.toml"},
				},
				{
					Name:     "node",
					Version:  "22",
					PURLType: purl.TypeMise,
					Metadata: &misemeta.Metadata{
						ToolName:    "node",
						ToolVersion: "22",
					},
					Locations: []string{"testdata/valid-mise.toml"},
				},
			},
		},
		{
			Name: "empty mise.toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-mise.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid toml",
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
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
