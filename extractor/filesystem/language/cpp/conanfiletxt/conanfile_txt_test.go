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

package conanfiletxt_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanfiletxt"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
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
			name:      "conanfile.txt",
			inputPath: "conanfile.txt",
			want:      true,
		},
		{
			name:      "path/to/conanfile.txt",
			inputPath: "path/to/my/conanfile.txt",
			want:      true,
		},
		{
			name:      "conanfile.txt/file",
			inputPath: "path/to/my/conanfile.txt/file",
			want:      false,
		},
		{
			name:      "conanfile.txt.file",
			inputPath: "path/to/my/conanfile.txt.file",
			want:      false,
		},
		{
			name:      "not conanfile.txt",
			inputPath: "path/to/my/package.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := conanfiletxt.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("conanfiletxt.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.txt",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-deps.txt",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-dep.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/one-dep.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name: "multiple dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multi-deps.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "poco",
					Version:  "1.9.4",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/multi-deps.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/multi-deps.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "boost",
					Version:  "1.70.0",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/multi-deps.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name: "comments skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/comments.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "poco",
					Version:  "1.9.4",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/comments.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "boost",
					Version:  "1.70.0",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/comments.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name: "with channels stripped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-channels.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-channels.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "poco",
					Version:  "1.9.4",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-channels.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "boost",
					Version:  "1.70.0",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-channels.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name: "mixed sections",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed-sections.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/mixed-sections.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "cmake",
					Version:  "3.23.0",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/mixed-sections.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"tool-requires"},
					},
				},
				{
					Name:     "7zip",
					Version:  "16.00",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/mixed-sections.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"tool-requires"},
					},
				},
			},
		},
		{
			Name: "with revisions stripped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-revisions.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-revisions.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "boost",
					Version:  "1.70.0",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-revisions.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "poco",
					Version:  "1.9.4",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/with-revisions.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
		{
			Name: "version ranges preserved",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/version-ranges.txt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "poco",
					Version:  "[>1.0 <1.9]",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/version-ranges.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
				{
					Name:     "zlib",
					Version:  "1.2.11",
					PURLType: purl.TypeConan,
					Location: extractor.LocationFromPath("testdata/version-ranges.txt"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"requires"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := conanfiletxt.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("conanfiletxt.New: %v", err)
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
