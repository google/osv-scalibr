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

package carthagecartfileresolved_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/carthagecartfileresolved"
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
			name:             "Cartfile.resolved file",
			path:             "Cartfile.resolved",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "path Cartfile.resolved file",
			path:             "path/to/my/Cartfile.resolved",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "test.resolved",
			wantRequired: false,
		},
		{
			name:             "Cartfile.resolved file required if file size < max file size",
			path:             "Cartfile.resolved",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Cartfile.resolved file required if file size == max file size",
			path:             "Cartfile.resolved",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Cartfile.resolved file not required if file size > max file size",
			path:             "Cartfile.resolved",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "Cartfile.resolved file required if max file size set to 0",
			path:             "Cartfile.resolved",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := carthagecartfileresolved.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("carthagecartfileresolved.New: %v", err)
			}
			e.(*carthagecartfileresolved.Extractor).Stats = collector

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
			Name: "valid_mixed_cartfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "github.com/Alamofire/Alamofire",
					Version:  "5.4.3",
					PURLType: purl.TypeSwift,
					Location: extractor.LocationFromPathAndLine("testdata/valid", 1),
				},
				{
					Name:     "github.com/SwiftyJSON/SwiftyJSON",
					Version:  "5.0.1",
					PURLType: purl.TypeSwift,
					Location: extractor.LocationFromPathAndLine("testdata/valid", 2),
				},
			},
		},
		{
			Name: "valid_github_only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/github_only",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "github.com/ReactiveX/RxSwift",
					Version:  "6.5.0",
					PURLType: purl.TypeSwift,
					Location: extractor.LocationFromPathAndLine("testdata/github_only", 1),
				},
			},
		},
		{
			Name: "valid_git_only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git_only",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "github.com/SwiftyJSON/SwiftyJSON",
					Version:  "5.0.1",
					PURLType: purl.TypeSwift,
					Location: extractor.LocationFromPathAndLine("testdata/git_only", 1),
				},
			},
		},
		{
			Name: "empty_cartfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "binary_skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/binary_only",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := carthagecartfileresolved.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("carthagecartfileresolved.New: %v", err)
			}
			e.(*carthagecartfileresolved.Extractor).Stats = collector

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
