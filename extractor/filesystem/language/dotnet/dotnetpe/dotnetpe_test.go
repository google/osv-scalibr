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

package dotnetpe_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			collector := testcollector.New()
			cfg := &cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes}
			e, err := dotnetpe.New(cfg)
			if err != nil {
				t.Fatalf("dotnetpe.New: %v", err)
			}
			e.(*dotnetpe.Extractor).Stats = collector

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
				{Name: "Flurl.Http.dll", Version: "4.0.2.0", PURLType: purl.TypeNuget},
				{Name: "HelloWorldApp.dll", Version: "1.0.0.0", PURLType: purl.TypeNuget},
				{Name: "Newtonsoft.Json.dll", Version: "13.0.0.0", PURLType: purl.TypeNuget},
				{Name: "System.Collections.dll", Version: "9.0.0.0", PURLType: purl.TypeNuget},
				{Name: "System.Console.dll", Version: "9.0.0.0", PURLType: purl.TypeNuget},
				{Name: "System.Net.Http.dll", Version: "9.0.0.0", PURLType: purl.TypeNuget},
				{Name: "System.Runtime.dll", Version: "9.0.0.0", PURLType: purl.TypeNuget},
			},
		},
		{
			Name: "valid .exe",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/HelloWorldApp.exe",
			},
			WantPackages: []*extractor.Package{
				{Name: "HelloWorldApp.dll", Version: "1.0.0.0", PURLType: purl.TypeNuget},
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
			extr, err := dotnetpe.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("dotnetpe.New: %v", err)
			}

			input := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, input)

			got, err := extr.Extract(t.Context(), &input)
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

func TestExtract_VirtualFSCleansUpTempDir(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	data, err := os.ReadFile("testdata/HelloWorldApp.exe")
	if err != nil {
		t.Fatalf("os.ReadFile: %v", err)
	}

	extr, err := dotnetpe.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("dotnetpe.New: %v", err)
	}

	input := &filesystem.ScanInput{
		Path:   "HelloWorldApp.exe",
		Root:   "",
		Info:   fakefs.FakeFileInfo{FileName: "HelloWorldApp.exe", FileMode: fs.ModePerm, FileSize: int64(len(data))},
		Reader: bytes.NewReader(data),
	}

	got, err := extr.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}
	if len(got.Packages) == 0 {
		t.Fatalf("Extract returned 0 packages, want >= 1")
	}

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q): %v", tmpDir, err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "scalibr-tmp") {
			t.Errorf("leaked temporary directory %q in %q after Extract", entry.Name(), tmpDir)
		}
	}
}
