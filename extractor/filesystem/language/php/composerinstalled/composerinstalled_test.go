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

package composerinstalled_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerinstalled"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "empty_path",
			path: "",
		},
		{
			name: "vendor_composer_installed",
			path: filepath.FromSlash("vendor/composer/installed.json"),
			want: true,
		},
		{
			name: "custom_vendor_directory",
			path: filepath.FromSlash("app/dependencies/composer/installed.json"),
			want: true,
		},
		{
			name: "wrong_parent_directory",
			path: filepath.FromSlash("vendor/installed.json"),
		},
		{
			name: "wrong_filename",
			path: filepath.FromSlash("vendor/composer/installed.php"),
		},
		{
			name: "additional_extension",
			path: filepath.FromSlash("vendor/composer/installed.json.backup"),
		},
	}

	extr, err := composerinstalled.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("composerinstalled.New: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extr.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "composer_2_format",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/v2/installed.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "symfony/console",
					Version:  "v7.3.4",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPathAndLine("testdata/v2/installed.json", 4),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d3a5e2f0bcdb73f3779467bfb3ae4e8e83c2e0e3",
					},
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
				{
					Name:     "phpunit/phpunit",
					Version:  "12.3.8",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPathAndLine("testdata/v2/installed.json", 12),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}},
				},
			},
		},
		{
			Name: "composer_1_format",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/v1/installed.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "guzzlehttp/guzzle",
					Version:  "6.5.8",
					PURLType: purl.TypeComposer,
					Location: extractor.LocationFromPathAndLine("testdata/v1/installed.json", 3),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "a52f0440530b54fa079ce76e8c5d196a42cad981",
					},
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{}},
				},
			},
		},
		{
			Name: "empty_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty/installed.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid_json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/installed.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "null_json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/null/installed.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "must contain an object or array"},
		},
		{
			Name: "missing_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-packages/installed.json",
			},
			WantErr: extracttest.ContainsErrStr{Str: "missing packages"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := composerinstalled.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("composerinstalled.New: %v", err)
			}
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			want := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
