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

package packageswift_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/packageswift"
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
			name:             "Package.swift file",
			path:             "Package.swift",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "path Package.swift file",
			path:             "path/to/my/Package.swift",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "wrong file name",
			path:         "test.swift",
			wantRequired: false,
		},
		{
			name:             "Package.swift file required if file size < max file size",
			path:             "Package.swift",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Package.swift file not required if file size > max file size",
			path:             "Package.swift",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := packageswift.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("packageswift.New: %v", err)
			}
			e.(*packageswift.Extractor).Stats = collector

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
			Name: "single from dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single_from",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/single_from")},
			},
		},
		{
			Name: "multiple mixed dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_mixed",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/multiple_mixed")},
				{Name: "github.com/apple/swift-nio", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/multiple_mixed")},
				{Name: "github.com/vapor/vapor", Version: "4.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/multiple_mixed")},
			},
		},
		{
			Name: "exact version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/exact_version",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.1.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/exact_version")},
			},
		},
		{
			Name: "dot exact version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dot_exact_version",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-nio", Version: "2.82.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/dot_exact_version")},
			},
		},
		{
			Name: "upToNextMinor",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/up_to_next_minor",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/up_to_next_minor")},
			},
		},
		{
			Name: "branch and revision ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/branch_revision",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "local path ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/local_path",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "comments and whitespace",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments_whitespace",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/comments_whitespace")},
				{Name: "github.com/apple/swift-nio", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/comments_whitespace")},
			},
		},
		{
			Name: "target product dependencies ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/target_deps",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/target_deps")},
			},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_deps",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "multiline package declaration",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiline",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/multiline")},
			},
		},
		{
			Name: "package dependencies append syntax",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/append_syntax",
			},
			WantPackages: []*extractor.Package{
				{Name: "github.com/apple/swift-crypto", Version: "2.0.0", PURLType: purl.TypeSwift, Location: extractor.LocationFromPath("testdata/append_syntax")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := packageswift.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("packageswift.New: %v", err)
			}
			e.(*packageswift.Extractor).Stats = collector

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
		})
	}
}
