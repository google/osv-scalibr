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

package cdn_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/cdn"
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
		want             bool
	}{
		{
			name: "html",
			path: "index.html",
			want: true,
		},
		{
			name: "nested_htm",
			path: "public/app.htm",
			want: true,
		},
		{
			name: "javascript_not_required",
			path: "app.js",
			want: false,
		},
		{
			name: "markdown_not_required",
			path: "README.md",
			want: false,
		},
		{
			name:             "too_large",
			path:             "index.html",
			fileSizeBytes:    2 * units.MiB,
			maxFileSizeBytes: 1 * units.MiB,
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
			}
			e, err := cdn.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("cdn.New: %v", err)
			}

			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if got != tt.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "html_script_and_importmap_cdns",
			path: "testdata/index.html",
			wantPackages: []*extractor.Package{
				{
					Name:     "lodash-es",
					Version:  "4.17.21",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/index.html"),
				},
				{
					Name:     "@scope/pkg",
					Version:  "2.3.4",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/index.html"),
				},
				{
					Name:     "vue",
					Version:  "3.4.21",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/index.html"),
				},
				{
					Name:     "react",
					Version:  "18.2.0",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/index.html"),
				},
				{
					Name:     "preact",
					Version:  "10.19.6",
					PURLType: purl.TypeNPM,
					Location: extractor.LocationFromPath("testdata/index.html"),
				},
			},
		},
		{
			name:         "no_supported_cdn_packages",
			path:         "testdata/no_packages.html",
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
				Path: tt.path,
			})
			defer extracttest.CloseTestScanInput(t, input)

			e, err := cdn.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cdn.New: %v", err)
			}
			got, err := e.Extract(t.Context(), &input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%s) error got %v, want %v", tt.path, err, tt.wantErr)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Extract(%s) diff (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
