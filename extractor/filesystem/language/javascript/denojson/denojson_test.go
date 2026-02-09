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

package denojson_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denojson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/denojson/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
	}{
		{
			name:         "deno.json at root",
			path:         "deno.json",
			wantRequired: true,
		},
		{
			name:         "top level deno.json",
			path:         "testdata/deno.json",
			wantRequired: true,
		},
		{
			name:         "not deno.json",
			path:         "testdata/test.js",
			wantRequired: false,
		},
		{
			name:             "deno.json required if size less than maxFileSizeBytes",
			path:             "deno.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 2000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "deno.json required if size equal to maxFileSizeBytes",
			path:             "deno.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     true,
		},
		{
			name:             "deno.json not required if size greater than maxFileSizeBytes",
			path:             "deno.json",
			fileSizeBytes:    10000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     false,
		},
		{
			name:             "deno.json required if maxFileSizeBytes explicitly set to 0",
			path:             "deno.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			e := denojson.New(denojson.Config{
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		cfg          denojson.Config
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "deno.json with basic fields",
			path: "testdata/deno.json",
			wantPackages: []*extractor.Package{
				{
					Name:      "chalk",
					Version:   "1.0.0",
					Locations: []string{"testdata/deno.json"},
					PURLType:  purl.TypeNPM,
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						URL: "npm:chalk@1",
					},
				},
				{
					Name:      "std1/path1",
					Version:   "^1",
					PURLType:  purl.TypeJSR,
					Locations: []string{"testdata/deno.json"},
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						URL: "jsr:@std1/path1@^1",
					},
				},
				//{
				//	Name:      "my-deno-app",
				//	Version:   "0.1.0",
				//	Locations: []string{"testdata/deno.json"},
				//	PURLType:  purl.TypeNPM,
				//	Metadata:  &metadata.JavascriptDenoJSONMetadata{},
				//},
			},
		},
		{
			name:    "invalid deno.json, json parse error",
			path:    "testdata/invalidDenoJson/deno.json",
			wantErr: cmpopts.AnyError,
		},
		{
			name: "typescript file contains direct package imports",
			path: "testdata/importSpecifiers.ts",
			wantPackages: []*extractor.Package{
				{
					Name:      "lodash-es",
					Version:   "4.17.22",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						FromUnpkgCDN: true,
						URL:          "https://unpkg.com/lodash-es@4.17.22/lodash.js",
					},
				},
				{
					Name:      "lodash-es",
					Version:   "4.17.21",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						FromUnpkgCDN: true,
						URL:          "https://unpkg.com/lodash-es@4.17.21/lodash.js",
					},
				},
				{
					Name:      "canvas-confetti",
					Version:   "1.6.0",
					PURLType:  purl.TypeNPM,
					Locations: []string{"testdata/importSpecifiers.ts"},
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						FromESMCDN: true,
						URL:        "https://esm.sh/canvas-confetti@1.6.0",
					},
				},
				{
					Name:      "openai",
					Version:   "4.69.0",
					Locations: []string{"testdata/importSpecifiers.ts"},
					PURLType:  purl.TypeNPM,
					Metadata: &metadata.JavascriptDenoJSONMetadata{
						FromDenolandCDN: true,
						URL:             "https://deno.land/x/openai@v4.69.0/mod.ts",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			scanInput := extracttest.GenerateScanInputMock(t,
				extracttest.ScanInputMockConfig{
					Path: tt.path,
				})
			e := denojson.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), &scanInput)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			var want inventory.Inventory
			if tt.wantPackages != nil {
				want = inventory.Inventory{Packages: tt.wantPackages}
			}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

// defaultConfigWith combines any non-zero fields of cfg with denojson.DefaultConfig().
func defaultConfigWith(cfg denojson.Config) denojson.Config {
	newCfg := denojson.DefaultConfig()

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
	return newCfg
}
