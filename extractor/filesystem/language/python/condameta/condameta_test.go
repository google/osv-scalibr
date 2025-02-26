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

package condameta_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condameta"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     condameta.Config
		wantCfg condameta.Config
	}{
		{
			name: "default",
			cfg:  condameta.DefaultConfig(),
			wantCfg: condameta.Config{
				MaxFileSizeBytes: 10 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: condameta.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: condameta.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := condameta.New(tt.cfg)
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
			name:             "valid path conda json file",
			path:             "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "non-toplevel dirs",
			path:         "path/to/envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			wantRequired: true,
		},
		{
			name:         "invalid envs dir",
			path:         "/path/to/fooenvs/conda-meta/numpy-1.21.2-py39h123abcde.json",
			wantRequired: false,
		},
		{
			name:         "invalid path conda json file",
			path:         "envs/data_analysis/test/numpy-1.21.2-py39h123abcde.json",
			wantRequired: false,
		},
		{
			name:         "invalid extension",
			path:         "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.txt",
			wantRequired: false,
		},
		{
			name:             "conda json file required if file size < max file size",
			path:             "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "conda json file required if file size == max file size",
			path:             "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "conda json file not required if file size > max file size",
			path:             "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "conda json file required if max file size set to 0",
			path:             "envs/data_analysis/conda-meta/numpy-1.21.2-py39h123abcde.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = condameta.New(condameta.Config{
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
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid conda file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "jupyterlab",
					Version:   "3.1.12",
					Locations: []string{"testdata/valid"},
				},
			},
		},
		{
			Name: "conda file not valid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid",
			},
			WantErr: cmpopts.AnyError,
		},
		{
			Name: "conda file empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantErr: cmpopts.AnyError,
		},
		{
			Name: "no package name",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/noname",
			},
			WantErr: cmpopts.AnyError,
		},
		{
			Name: "no package version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/noversion",
			},
			WantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = condameta.New(condameta.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100,
			})

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := condameta.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    "name",
		Version: "1.2.3",
	}
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
