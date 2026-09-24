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

package cabal_test

import (
	"errors"
	"io/fs"
	"path/filepath"
	"testing"
	"testing/iotest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
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
			name:             "cabal package database conf file 1",
			path:             "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal package database conf file 2",
			path:             "home/user/.cabal/store/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal package database conf file required if file size < max file size",
			path:             "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal package database conf file required if file size == max file size",
			path:             "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal package database conf file not required if file size > max file size",
			path:             "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "cabal package database conf file required if max file size is zero",
			path:             "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "conf file outside package.db",
			path:         "home/user/.local/state/cabal/store/ghc-9.6.6/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			wantRequired: false,
		},
		{
			name:         "conf file outside cabal store",
			path:         "home/user/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			wantRequired: false,
		},
		{
			name:         "non-conf file",
			path:         "home/user/.local/state/cabal/store/ghc-9.6.6/package.db/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.txt",
			wantRequired: false,
		},
		{
			name:         "directory",
			path:         "home/user/.local/state/cabal/store/ghc-9.6.6/package.db",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()

			e, err := cabal.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			e.(*cabal.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(
				tt.path,
				fakefs.FakeFileInfo{
					FileName: filepath.Base(tt.path),
					FileMode: fs.ModePerm,
					FileSize: fileSizeBytes,
				},
			))

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
			Name: "safe package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "safe",
					Version:  "0.3.21",
					PURLType: purl.TypeHackage,
					Location: extractor.LocationFromPath("testdata/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf"),
				},
			},
		},
		{
			Name: "haskell-say package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/haskell-say-1.0.0.0-5a24666dc582c5d8e5cc9a1949ec4a9b927455ffb058881d1398f193add47c08.conf",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "haskell-say",
					Version:  "1.0.0.0",
					PURLType: purl.TypeHackage,
					Location: extractor.LocationFromPath("testdata/haskell-say-1.0.0.0-5a24666dc582c5d8e5cc9a1949ec4a9b927455ffb058881d1398f193add47c08.conf"),
				},
			},
		},
		{
			Name: "abx2xml-go package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/abx2xml-go-1.0-6a24666dc582c5d8e5cc9a1949ec4a9b927455ffb058881d1398f193add47c00.conf",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "abx2xml-go",
					Version:  "1.0",
					PURLType: purl.TypeHackage,
					Location: extractor.LocationFromPath("testdata/abx2xml-go-1.0-6a24666dc582c5d8e5cc9a1949ec4a9b927455ffb058881d1398f193add47c00.conf"),
				},
			},
		},
		{
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid",
			},
			WantPackages: []*extractor.Package{},
			WantErr:      cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()

			e, err := cabal.New(&cpb.PluginConfig{
				MaxFileSizeBytes: 30 * units.MiB,
			})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}

			e.(*cabal.Extractor).Stats = collector

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{
				Packages: tt.WantPackages,
			}

			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

func TestExtract_ScannerError(t *testing.T) {
	e, err := cabal.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("cabal.New: %v", err)
	}

	input := &filesystem.ScanInput{
		Path:   "home/user/.local/state/cabal/store/ghc-9.6.6/safe-0.3.21-bf7883b24e2927b8c2c172a7483f6c3e88459b69f9bf915968d889e82f47f177.conf",
		Reader: iotest.ErrReader(errors.New("mock read error")),
	}

	wantErr := extracttest.ContainsErrStr{Str: "error while scanning cabal store conf file: mock read error"}
	_, err = e.Extract(t.Context(), input)
	if diff := cmp.Diff(wantErr, err, cmpopts.EquateErrors()); diff != "" {
		t.Errorf("e.Extract() error diff (-want +got):\n%s", diff)
	}
}
