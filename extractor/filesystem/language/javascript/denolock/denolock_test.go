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

package denolock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denolock"
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
		{name: "empty path", inputPath: "", want: false},
		{name: "deno.lock at root", inputPath: "deno.lock", want: true},
		{name: "nested deno.lock", inputPath: "path/to/my/deno.lock", want: true},
		{name: "deno.lock as a directory", inputPath: "path/to/my/deno.lock/file", want: false},
		{name: "deno.lock as a suffix", inputPath: "path/to/my/deno.lock.file", want: false},
		{name: "deno.lock inside node_modules", inputPath: "foo/node_modules/bar/deno.lock", want: false},
		{name: "unrelated file", inputPath: "path/to/deno.json", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := denolock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("denolock.New: %v", err)
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
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "empty object",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one npm package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-npm-package.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "chalk",
					Version:  "5.4.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/one-npm-package.json"),
				},
			},
		},
		{
			Name: "one jsr package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-jsr-package.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "std/internal",
					Version:  "1.0.6",
					PURLType: purl.TypeJSR,
					Location: extractor.LocationFromPath("testdata/one-jsr-package.json"),
				},
			},
		},
		{
			Name: "mixed npm and jsr packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "std/assert",
					Version:  "1.0.13",
					PURLType: purl.TypeJSR,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
				{
					Name:     "std/internal",
					Version:  "1.0.6",
					PURLType: purl.TypeJSR,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
				{
					Name:     "@types/node",
					Version:  "22.5.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
				{
					Name:     "chalk",
					Version:  "5.4.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
				{
					Name:     "string_decoder",
					Version:  "1.3.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
				{
					Name:     "undici-types",
					Version:  "6.19.8",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/mixed.json"),
				},
			},
		},
		{
			Name: "npm packages with peer-dependency suffixes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "@babel/core",
					Version:  "7.26.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/peer-dependencies.json"),
				},
				{
					Name:     "debug",
					Version:  "4.3.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/peer-dependencies.json"),
				},
			},
		},
		{
			Name: "malformed package keys are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed-package-key.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "chalk",
					Version:  "5.4.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/malformed-package-key.json"),
				},
			},
		},
		{
			Name: "v3 lockfile with nested packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/v3-packages.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "chalk",
					Version:  "5.4.1",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/v3-packages.json"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := denolock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("denolock.New: %v", err)
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
