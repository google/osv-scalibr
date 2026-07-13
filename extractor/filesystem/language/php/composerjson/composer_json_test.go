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

package composerjson_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerjson"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
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
			name:             "composer.json at root",
			path:             "composer.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "composer.json in subpath",
			path:             "path/to/composer.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not composer.json",
			path:         "package.json",
			wantRequired: false,
		},
		{
			name:             "size under limit",
			path:             "composer.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "size over limit",
			path:             "composer.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := composerjson.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("composerjson.New: %v", err)
			}
			e.(*composerjson.Extractor).Stats = collector

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
			Name: "single dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single_dep",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/single_dep"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "multiple dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_deps",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/multiple_deps"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
				{Name: "monolog/monolog", Version: "2.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/multiple_deps"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "require dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/require_dev",
			},
			WantPackages: []*extractor.Package{
				{Name: "phpunit/phpunit", Version: "9.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/require_dev"), Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}}},
			},
		},
		{
			Name: "mixed require and require dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/mixed"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
				{Name: "phpunit/phpunit", Version: "9.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/mixed"), Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"dev"}}},
			},
		},
		{
			Name: "version constraints",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/version_constraints",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/version_constraints"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
				{Name: "monolog/monolog", Version: "2.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/version_constraints"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
				{Name: "doctrine/orm", Version: "2.8.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/version_constraints"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
				{Name: "twig/twig", Version: "3.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/version_constraints"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "or constraint",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/or_constraint",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/or_constraint"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "platform packages skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/platform_skipped",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/platform_skipped"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "wildcard and branch skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/wildcard_skipped",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/wildcard_skipped"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "extra sections ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extra_sections",
			},
			WantPackages: []*extractor.Package{
				{Name: "symfony/console", Version: "5.0.0", PURLType: purl.TypeComposer, Location: extractor.LocationFromPath("testdata/extra_sections"), Metadata: &osv.DepGroupMetadata{DepGroupVals: nil}},
			},
		},
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid_json",
			},
			WantErr: cmpopts.AnyError,
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_deps",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := composerjson.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("composerjson.New: %v", err)
			}
			e.(*composerjson.Extractor).Stats = collector

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
