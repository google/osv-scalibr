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

package conanlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_Extract_v1(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantInventory: nil,
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v1.json",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/one-package.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "no name",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-name.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/no-name.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/two-packages.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/two-packages.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					Locations: []string{"testdata/nested-dependencies.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					Locations: []string{"testdata/one-package-dev.v1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format00",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/old-format-0.0.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.0.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format01",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/old-format-0.1.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.1.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format02",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/old-format-0.2.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.2.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "old format03",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/old-format-0.3.json",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					Locations: []string{"testdata/old-format-0.3.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := conanlock.Extractor{}

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
