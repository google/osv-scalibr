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

package paketlock_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/paketlock"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			name:             "paket.lock file",
			path:             "paket.lock",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "path paket.lock file",
			path:             "path/to/my/paket.lock",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "paket.dependencies",
			wantRequired: false,
		},
		{
			name:         "file not required",
			path:         "paket.references",
			wantRequired: false,
		},
		{
			name:         "file not required",
			path:         "packages.config",
			wantRequired: false,
		},
		{
			name:             "paket.lock file required if file size < max file size",
			path:             "paket.lock",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "paket.lock file required if file size == max file size",
			path:             "paket.lock",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "paket.lock file not required if file size > max file size",
			path:             "paket.lock",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "paket.lock file required if max file size set to 0",
			path:             "paket.lock",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := paketlock.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*paketlock.Extractor).Stats = collector

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
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid paket.lock file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/paket.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "NUnit",
					Version:   "2.6.4",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "FSharp.Core",
					Version:   "4.5.0",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "Newtonsoft.Json",
					Version:   "12.0.3",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "Microsoft.Extensions.Logging",
					Version:   "6.0.0",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "FAKE",
					Version:   "5.20.4",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "Paket",
					Version:   "7.0.0",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.lock"},
				},
				{
					Name:      "fsprojects/Paket",
					Version:   "5.0.0",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/fsprojects/Paket",
					},
				},
				{
					Name:      "fsharp/FAKE",
					Version:   "5.20.4",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/fsharp/FAKE",
					},
				},
			},
		},
		{
			Name: "paket.lock file not valid format",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-lock/paket.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty paket.lock file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-lock-dir/paket.lock",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := paketlock.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*paketlock.Extractor).Stats = collector

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.InputConfig.Path)
			if tt.WantErr == nil && gotResultMetric != stats.FileExtractedResultSuccess {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.InputConfig.Path, gotResultMetric, stats.FileExtractedResultSuccess)
			}
		})
	}
}
