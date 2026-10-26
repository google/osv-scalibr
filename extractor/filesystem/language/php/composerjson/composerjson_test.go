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

package composerjson_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerjson"
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
			name:      "empty name",
			inputPath: "",
			want:      false,
		},
		{
			name:      "composer.json from root",
			inputPath: "composer.json",
			want:      true,
		},
		{
			name:      "composer.json from subpath",
			inputPath: "path/to/my/composer.json",
			want:      true,
		},
		{
			name:      "composer.json as a dir",
			inputPath: "path/to/my/composer.json/file",
			want:      false,
		},
		{
			name:      "composer.json with additional extension",
			inputPath: "path/to/my/composer.json.file",
			want:      false,
		},
		{
			name:      "composer.json as substring",
			inputPath: "path.to.my.composer.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := composerjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("composerjson.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "null json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/null.jsontest",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "require only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/require-only.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "monolog/monolog",
					Version:  "2.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/require-only.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "symfony/console",
					Version:  "5.4.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/require-only.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "require dev only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/require-dev-only.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "phpunit/phpunit",
					Version:  "9.5.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/require-dev-only.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "require and require dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/both.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "monolog/monolog",
					Version:  "2.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/both.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "symfony/console",
					Version:  "5.4.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/both.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "phpunit/phpunit",
					Version:  "9.5.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/both.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "platform packages are filtered out",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/platform.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "monolog/monolog",
					Version:  "2.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/platform.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "phpunit/phpunit",
					Version:  "9.5.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/platform.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "constraints resolve to minimum version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/resolution.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "vendor/exact",
					Version:  "1.2.3",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/caret",
					Version:  "3.4.5",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/tilde",
					Version:  "2.3.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/range",
					Version:  "1.5.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/wildcard",
					Version:  "0.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/or",
					Version:  "7.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/resolution.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "whitespace after comparison operators is accepted",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/whitespace.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "vendor/gte",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/gt",
					Version:  "1.2.3.1",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/eq",
					Version:  "1.2.3",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/lt",
					Version:  "0.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/not-eq",
					Version:  "1.0.0.1",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/range",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/or",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/dev-gte",
					Version:  "5.6.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/whitespace.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "pre-release and patch suffixes are kept, build and stability suffixes are ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/suffixes.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "vendor/caret-prerelease",
					Version:  "1.2.3-beta1",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/tilde-prerelease",
					Version:  "1.2.3-alpha",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/exact-prerelease",
					Version:  "1.2.3-RC2",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/caret-patch",
					Version:  "1.2.3-patch1",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/stable-suffix",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/gte-dev",
					Version:  "1.0.0-alpha",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/build",
					Version:  "1.2.3",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/caret-flag",
					Version:  "1.0.0-alpha",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/gte-flag",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/exact-flag",
					Version:  "1.0.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/suffixes.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "unresolvable constraints are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/fallback.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "vendor/valid",
					Version:  "1.2.3",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/fallback.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "vendor/dev-valid",
					Version:  "4.5.0",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPath("testdata/fallback.json"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := composerjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("composerjson.New: %v", err)
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
