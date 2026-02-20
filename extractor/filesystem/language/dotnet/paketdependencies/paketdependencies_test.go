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

package paketdependencies_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/paketdependencies"
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
			name:             "paket.dependencies file",
			path:             "paket.dependencies",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "path paket.dependencies file",
			path:             "path/to/my/paket.dependencies",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "paket.lock",
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
			name:             "paket.dependencies file required if file size < max file size",
			path:             "paket.dependencies",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "paket.dependencies file required if file size == max file size",
			path:             "paket.dependencies",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "paket.dependencies file not required if file size > max file size",
			path:             "paket.dependencies",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "paket.dependencies file required if max file size set to 0",
			path:             "paket.dependencies",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := paketdependencies.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*paketdependencies.Extractor).Stats = collector

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
			Name: "valid paket.dependencies file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/paket.dependencies",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "NUnit",
					Version:   "2.6.3",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "FSharp.Core",
					Version:   "4.0.0",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "Newtonsoft.Json",
					Version:   "12.0.3",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "Microsoft.Extensions.Logging",
					Version:   "",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "FAKE",
					Version:   "",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "Paket",
					Version:   "",
					PURLType:  purl.TypeNuget,
					Locations: []string{"testdata/paket.dependencies"},
				},
				{
					Name:      "fsprojects/Paket",
					Version:   "",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.dependencies"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/fsprojects/Paket",
					},
				},
				{
					Name:      "fsharp/FAKE",
					Version:   "5.20.4",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.dependencies"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/fsharp/FAKE",
					},
				},
				{
					Name:      "tpetricek/FSharp.Formatting",
					Version:   "",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.dependencies"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/tpetricek/FSharp.Formatting",
					},
				},
				{
					Name:      "tpetricek/FSharp.Formatting",
					Version:   "2.13.5",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.dependencies"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo: "https://github.com/tpetricek/FSharp.Formatting",
					},
				},
				{
					Name:      "tpetricek/FSharp.Formatting",
					Version:   "",
					PURLType:  purl.TypeGithub,
					Locations: []string{"testdata/paket.dependencies"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Repo:   "https://github.com/tpetricek/FSharp.Formatting",
						Commit: "30cd5366a4f3f25a443ca4cd62cd592fd16ac69",
					},
				},
			},
		},
		{
			Name: "paket.dependencies file not valid format",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/paket.dependencies",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty paket.dependencies file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty-deps/paket.dependencies",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := paketdependencies.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*paketdependencies.Extractor).Stats = collector

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
