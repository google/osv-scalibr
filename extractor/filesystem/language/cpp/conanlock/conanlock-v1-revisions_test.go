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
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_Extract_v1_revisions(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/one-package.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "no name",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-name.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/no-name.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "zlib",
					Version:   "1.2.11",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/two-packages.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/two-packages.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "zlib",
					Version:   "1.2.13",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "bzip2",
					Version:   "1.0.8",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "freetype",
					Version:   "2.12.1",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "libpng",
					Version:   "1.6.39",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "brotli",
					Version:   "1.0.9",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/nested-dependencies.v1.revisions.json"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.v1.revisions.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "ninja",
					Version:   "1.11.1",
					PURLType:  purl.TypeConan,
					Locations: []string{"testdata/one-package-dev.v1.revisions.json"},
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

			got, err := extr.Extract(context.Background(), &scanInput)

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
