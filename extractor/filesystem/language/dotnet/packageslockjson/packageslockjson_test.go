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

package packageslockjson_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
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
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "some project's packages.lock.json",
			path:             "project/packages.lock.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "just packages.lock.json",
			path:             "packages.lock.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "non packages.lock.json",
			path:         "project/some.csproj",
			wantRequired: false,
		},
		{
			name:             "packages.lock.json required if file size < max file size",
			path:             "project/packages.lock.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "packages.lock.json required if file size == max file size",
			path:             "project/packages.lock.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "packages.lock.json not required if file size > max file size",
			path:             "project/packages.lock.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "packages.lock.json required if max file size set to 0",
			path:             "project/packages.lock.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = packageslockjson.New(
				packageslockjson.Config{
					Stats:            collector,
					MaxFileSizeBytes: test.maxFileSizeBytes,
				},
			)

			// Set default size if not provided.
			fileSizeBytes := test.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(test.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(test.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != test.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", test.path, isRequired, test.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(test.path)
			if gotResultMetric != test.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", test.path, gotResultMetric, test.wantResultMetric)
			}
		})
	}
}

func TestExtractor(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid packages.lock.json",
			path: "testdata/valid/packages.lock.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "Core.Dep",
					Version:   "1.24.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Dep.One",
					Version:   "1.1.1",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Dep.Two",
					Version:   "4.6.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Dep.Three",
					Version:   "1.0.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Dep.Four",
					Version:   "4.5.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Longer.Name.Dep",
					Version:   "4.7.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Some.Dep.Five",
					Version:   "4.7.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
				{
					Name:      "Another.Longer.Name.Dep",
					Version:   "4.5.4",
					Locations: []string{"testdata/valid/packages.lock.json"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "non json input",
			path:             "testdata/invalid/invalid",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = packageslockjson.New(packageslockjson.Config{Stats: collector})

			r, err := os.Open(test.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(test.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   test.path,
				Reader: r,
				Info:   info,
			}
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", test.name, err, test.wantErr)
			}

			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(test.wantInventory, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", test.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(test.path)
			if gotResultMetric != test.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", test.path, gotResultMetric, test.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(test.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", test.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := packageslockjson.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeNuget,
		Name:    "Name",
		Version: "1.2.3",
	}
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
