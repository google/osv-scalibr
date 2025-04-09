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

package dotnetpe_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		// fileSizeBytes is set to 1K if not specified because the minimum size of a PE file is
		// 	pe.TinyPESize // 97
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "executable file",
			path:             "test.exe",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "executable file with upper case",
			path:             "test.Exe",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             ".dll",
			path:             "test.dll",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "upper case .dll",
			path:             "test.DLL",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file without extension",
			path:             "test",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "relative path",
			path:             "path/to/my/test.exe",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "windows full path",
			path:             `C:\\path\\to\\my\\test.exe`,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "/test.deps",
			wantRequired: false,
		},
		{
			name:             "file required if file size < max file size",
			path:             "test.exe",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file not required if file size > max file size",
			path:             "test.exe",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := dotnetpe.DefaultConfig()
			collector := testcollector.New()
			cfg.Stats = collector
			if tt.maxFileSizeBytes != 0 {
				cfg.MaxFileSizeBytes = tt.maxFileSizeBytes
			}
			var e filesystem.Extractor = dotnetpe.New(cfg)

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
			Name: "valid .dll",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/HelloWorldApp.dll",
			},
			WantPackages: []*extractor.Package{
				{Name: "Flurl.Http.dll", Version: "4.0.2.0"},
				{Name: "HelloWorldApp.dll", Version: "1.0.0.0"},
				{Name: "Newtonsoft.Json.dll", Version: "13.0.0.0"},
				{Name: "System.Collections.dll", Version: "9.0.0.0"},
				{Name: "System.Console.dll", Version: "9.0.0.0"},
				{Name: "System.Net.Http.dll", Version: "9.0.0.0"},
				{Name: "System.Runtime.dll", Version: "9.0.0.0"},
			},
		},
		{
			Name: "valid .exe",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/HelloWorldApp.exe",
			},
			WantPackages: []*extractor.Package{
				{Name: "HelloWorldApp.dll", Version: "1.0.0.0"},
			},
		},
		{
			Name: "Empty .dll",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/Empty.dll",
			},
			WantErr: extracttest.ContainsErrStr{Str: "the file header does not contain magic bytes"},
		},
		{
			Name: "Invalid .dll",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/Invalid.dll",
			},
			WantErr: extracttest.ContainsErrStr{Str: "the file header does not contain magic bytes"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := dotnetpe.New(dotnetpe.DefaultConfig())

			input := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(context.Background(), &input)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantPackages, got.Packages, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
