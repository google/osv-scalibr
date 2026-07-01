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

package gemfile_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfile"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "Gemfile",
			want:      true,
		},
		{
			inputPath: "path/to/Gemfile",
			want:      true,
		},
		{
			inputPath: "Gemfile.lock",
			want:      false,
		},
		{
			inputPath: "path/to/Gemfile.lock",
			want:      false,
		},
		{
			inputPath: "path/to/MyGemfile",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := gemfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gemfile.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: nil,
		},
		{
			Name: "basic gems",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "rails",
					Version:  "~> 7.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "pg",
					Version:  "~> 1.1",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "puma",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "nokogiri",
					Version:  "~> 1.16",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "debug-tools",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "byebug",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
			},
		},
		{
			Name: "edge cases with options",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/edge",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "sprockets-rails",
					Version:  ">= 2.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "propshaft",
					Version:  ">= 0.1.7",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "releaser",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
				{
					Name:     "rack",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/edge"),
				},
			},
		},
		{
			Name: "real rails Gemfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/rails",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "minitest",
					Version:  "~> 6.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rails"),
				},
				{
					Name:     "minitest-mock",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rails"),
				},
				{
					Name:     "releaser",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rails"),
				},
				{
					Name:     "sprockets-rails",
					Version:  ">= 2.0.0",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rails"),
				},
				{
					Name:     "propshaft",
					Version:  ">= 0.1.7",
					PURLType: purl.TypeGem,
					Location: extractor.LocationFromPath("testdata/rails"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := gemfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gemfile.New: %v", err)
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
