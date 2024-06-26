// Copyright 2024 Google LLC
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

package packagelockjson_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "package-lock.json",
			path:             "foo/package-lock.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "package.json",
			path:         "foo/package.json",
			wantRequired: false,
		},
		{
			name:         "asdf.json",
			path:         "foo/asdf.json",
			wantRequired: false,
		},
		{
			name:         "foo-package-lock.json",
			path:         "foo-package-lock.json",
			wantRequired: false,
		},
		{
			name:             "package-lock.json required if file size < max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package-lock.json required if file size == max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 1 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package-lock.json not required if file size > max file size",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "package-lock.json required if max file size set to 0",
			path:             "foo/package-lock.json",
			fileSizeBytes:    1 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = packagelockjson.New(
				packagelockjson.Config{
					Stats:            collector,
					MaxFileSizeBytes: tt.maxFileSizeBytes,
				},
			)

			// Set default size if not provided.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			isRequired := e.FileRequired(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			})
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
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
			name: "package-lock.v1",
			path: "testdata/package-lock.v1.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"testdata/package-lock.v1.json"},
				},
				&extractor.Inventory{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"testdata/package-lock.v1.json"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "package-lock.v2",
			path: "testdata/package-lock.v2.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"testdata/package-lock.v2.json"},
				},
				&extractor.Inventory{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"testdata/package-lock.v2.json"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid json",
			path:             "testdata/invalid.json",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "not json",
			path:             "testdata/notjson",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = packagelockjson.New(packagelockjson.Config{Stats: collector})

			r, err := os.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{Path: tt.path, Reader: r, Info: info}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantInventory, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := packagelockjson.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeNPM,
		Name:    "name",
		Version: "1.2.3",
	}
	got, err := e.ToPURL(i)
	if err != nil {
		t.Fatalf("ToPURL(%v): %v", i, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
