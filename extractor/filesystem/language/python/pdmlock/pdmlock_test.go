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

package pdmlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestPdmExtractor_FileRequired(t *testing.T) {
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
			name:      "plain",
			inputPath: "pdm.lock",
			want:      true,
		},
		{
			name:      "absolute",
			inputPath: "/path/to/pdm.lock",
			want:      true,
		},
		{
			name:      "relative",
			inputPath: "../../pdm.lock",
			want:      true,
		},
		{
			name:      "in-path",
			inputPath: "/path/with/pdm.lock/in/middle",
			want:      false,
		},
		{
			name:      "invalid-suffix",
			inputPath: "pdm.lock.file",
			want:      false,
		},
		{
			name:      "invalid-prefix",
			inputPath: "project.name.pdm.lock",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := pdmlock.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
			WantInventory: nil,
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.toml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "single package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single-package.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/single-package.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/two-packages.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "six",
					Version:   "1.16.0",
					Locations: []string{"testdata/two-packages.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "package with dev dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dev-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"testdata/dev-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "package with optional dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "pyroute2",
					Version:   "0.7.11",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
				{
					Name:      "win-inet-pton",
					Version:   "1.1.0",
					Locations: []string{"testdata/optional-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"optional"},
					},
				},
			},
		},
		{
			Name: "package with git dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git-dependency.toml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "toml",
					Version:   "0.10.2",
					Locations: []string{"testdata/git-dependency.toml"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "65bab7582ce14c55cdeec2244c65ea23039c9e6f",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pdmlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
