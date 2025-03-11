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

package cargoauditable_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		mode             fs.FileMode
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "executable required if size less than maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    100,
			maxFileSizeBytes: 1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable required if size equal to maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable not required if size greater than maxFileSizeBytes",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 100,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "executable required if maxFileSizeBytes explicitly set to 0",
			path:             "some/path/a",
			mode:             0766,
			fileSizeBytes:    1000,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := cargoauditable.New(cargoauditable.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: tt.mode,
				FileSize: fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	cargoAuditableExtractor := cargoauditable.Extractor{}
	inventory := &extractor.Inventory{
		Name:      "name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeCargo,
		Name:    "name",
		Version: "1.2.3",
	}
	got := cargoAuditableExtractor.ToPURL(inventory)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", inventory, diff)
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "uses_serde_json",
			path: "testdata/uses_serde_json/uses_serde_json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "itoa",
					Version:   "1.0.14",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "memchr",
					Version:   "2.7.4",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "proc-macro2",
					Version:   "1.0.92",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "quote",
					Version:   "1.0.38",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "ryu",
					Version:   "1.0.18",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "serde",
					Version:   "1.0.217",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "serde_derive",
					Version:   "1.0.217",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "serde_json",
					Version:   "1.0.135",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "syn",
					Version:   "2.0.95",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "unicode-ident",
					Version:   "1.0.14",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
				{
					Name:      "uses_json",
					Version:   "0.1.0",
					Locations: []string{"testdata/uses_serde_json/uses_serde_json"},
				},
			},
		},
		{
			name: "no_deps",
			path: "testdata/no_deps/no_deps",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "no_deps",
					Version:   "0.1.0",
					Locations: []string{"testdata/no_deps/no_deps"},
				},
			},
		},
		{
			name:             "not_binary",
			path:             "testdata/not_binary/not_binary",
			wantInventory:    []*extractor.Inventory{},
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.path)
			if err != nil {
				t.Fatalf("os.Open(%s) unexpected error: %v", tt.path, err)
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat() for %q unexpected error: %v", tt.path, err)
			}

			collector := testcollector.New()

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: f}

			e := cargoauditable.New(cargoauditable.Config{Stats: collector})
			got, err := e.Extract(t.Context(), input)
			if err != tt.wantErr {
				t.Fatalf("Extract(%s) got error: %v, want error: %v", tt.path, err, tt.wantErr)
			}
			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantInventory, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Fatalf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && tt.wantErr == nil {
				wantResultMetric = stats.FileExtractedResultSuccess
			}
			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
