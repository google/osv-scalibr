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

package depsjson_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     depsjson.Config
		wantCfg depsjson.Config
	}{
		{
			name: "default",
			cfg:  depsjson.DefaultConfig(),
			wantCfg: depsjson.Config{
				MaxFileSizeBytes: 10 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: depsjson.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: depsjson.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := depsjson.New(tt.cfg)
			if diff := cmp.Diff(tt.wantCfg, got.Config()); diff != "" {
				t.Errorf("New(%+v).Config(): (-want +got):\n%s", tt.cfg, diff)
			}
		})
	}
}

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
			name:             "application1.deps.json file",
			path:             "application1.deps.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "path application1.deps.json file",
			path:             "path/to/my/application1.deps.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "/test.deps",
			wantRequired: false,
		},
		{
			name:             "application1.deps.json file required if file size < max file size",
			path:             "application1.deps.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "application1.deps.json file required if file size == max file size",
			path:             "application1.deps.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "application1.deps.json file not required if file size > max file size",
			path:             "application1.deps.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "application1.deps.json file required if max file size set to 0",
			path:             "application1.deps.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = depsjson.New(depsjson.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              depsjson.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid application1.deps.json file",
			path: "testdata/valid",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "TestLibrary",
					Version: "1.0.0",
					Metadata: &depsjson.Metadata{
						PackageName:    "TestLibrary",
						PackageVersion: "1.0.0",
						Type:           "project",
					},
					Locations: []string{"testdata/valid"},
				},
				{
					Name:    "AWSSDK.Core",
					Version: "3.7.10.6",
					Metadata: &depsjson.Metadata{
						PackageName:    "AWSSDK.Core",
						PackageVersion: "3.7.10.6",
						Type:           "package",
					},
					Locations: []string{"testdata/valid"},
				},
				{
					Name:    "Microsoft.Extensions.DependencyInjection",
					Version: "6.0.0",
					Metadata: &depsjson.Metadata{
						PackageName:    "Microsoft.Extensions.DependencyInjection",
						PackageVersion: "6.0.0",
						Type:           "package",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "application1.deps.json file not json",
			path:             "testdata/invalid",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "application1.deps.json file empty",
			path:             "testdata/empty",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "valid application1.deps.json file with an invalid package",
			path: "testdata/nopackagename",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "TestLibrary",
					Version: "1.0.0",
					Metadata: &depsjson.Metadata{
						PackageName:    "TestLibrary",
						PackageVersion: "1.0.0",
						Type:           "project",
					},
					Locations: []string{"testdata/nopackagename"},
				},
				{
					Name:    "AWSSDK.Core",
					Version: "3.7.10.6",
					Metadata: &depsjson.Metadata{
						PackageName:    "AWSSDK.Core",
						PackageVersion: "3.7.10.6",
						Type:           "package",
					},
					Locations: []string{"testdata/nopackagename"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = depsjson.New(depsjson.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100,
			})

			d := t.TempDir()

			// Opening and Reading the Test File
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

			input := &filesystem.ScanInput{
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info,
			}

			got, err := e.Extract(t.Context(), input)

			if diff := cmp.Diff(tt.wantInventory, got, cmpopts.SortSlices(invLess)); diff != "" {
				t.Errorf("Inventory mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func invLess(i1, i2 *extractor.Inventory) bool {
	return i1.Name < i2.Name
}

func TestToPURL(t *testing.T) {
	e := depsjson.Extractor{}
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
