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

package setupcfg_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setupcfg"
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
			name:             "setup.cfg file",
			path:             "pkg/setup.cfg",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.cfg required if file size < max file size",
			path:             "pkg/setup.cfg",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.cfg required if file size == max file size",
			path:             "pkg/setup.cfg",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.cfg not required if file size > max file size",
			path:             "pkg/setup.cfg",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "setup.cfg required if max file size set to 0",
			path:             "pkg/setup.cfg",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "setup.py is not setup.cfg",
			path:         "pkg/setup.py",
			wantRequired: false,
		},
		{
			name:         "setup.cfg.bak is not setup.cfg",
			path:         "pkg/setup.cfg.bak",
			wantRequired: false,
		},
		{
			name:         "setup.cfg as directory",
			path:         "pkg/setup.cfg/inner",
			wantRequired: false,
		},
		{
			name:         "uppercase SETUP.CFG is not matched",
			path:         "pkg/SETUP.CFG",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := setupcfg.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("setupcfg.New(%v) error: %v", tt.maxFileSizeBytes, err)
			}
			e.(*setupcfg.Extractor).Stats = collector

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
			Name: "basic install_requires and extras_require",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 7),
					Metadata: &setupcfg.Metadata{VersionComparator: ">="},
				},
				{
					Name:     "importlib-metadata",
					Version:  "6.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 8),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "flask",
					Version:  "3.1.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 9),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "numpy",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 10),
					Metadata: &setupcfg.Metadata{},
				},
				{
					Name:     "pytest",
					Version:  "7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 14),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "dev"},
				},
				{
					Name:     "black",
					Version:  "23.1.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/basic.cfg", 15),
					Metadata: &setupcfg.Metadata{VersionComparator: "==", DepGroup: "dev"},
				},
			},
		},
		{
			Name: "multiple extras_require groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extras.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/extras.cfg", 3),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "pytest",
					Version:  "7.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/extras.cfg", 7),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "dev"},
				},
				{
					Name:     "coverage",
					Version:  "7.4",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/extras.cfg", 8),
					Metadata: &setupcfg.Metadata{VersionComparator: "~=", DepGroup: "dev"},
				},
				{
					Name:     "sphinx",
					Version:  "5.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/extras.cfg", 10),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "docs"},
				},
				{
					Name:     "myst-parser",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/extras.cfg", 11),
					Metadata: &setupcfg.Metadata{DepGroup: "docs"},
				},
			},
		},
		{
			Name: "environment markers are stripped not evaluated",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/markers.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.20.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/markers.cfg", 3),
					Metadata: &setupcfg.Metadata{VersionComparator: ">="},
				},
				{
					Name:     "importlib-metadata",
					Version:  "6.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/markers.cfg", 4),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "dataclasses",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/markers.cfg", 5),
					Metadata: &setupcfg.Metadata{},
				},
				{
					Name:     "pytest",
					Version:  "7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/markers.cfg", 9),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "dev"},
				},
			},
		},
		{
			Name: "inline and full-line comments are ignored",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.cfg", 3),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "flask",
					Version:  "2.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.cfg", 6),
					Metadata: &setupcfg.Metadata{VersionComparator: ">="},
				},
				{
					Name:     "numpy",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.cfg", 7),
					Metadata: &setupcfg.Metadata{},
				},
				{
					Name:     "pytest",
					Version:  "7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.cfg", 11),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "dev"},
				},
				{
					Name:     "black",
					Version:  "23.1.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.cfg", 12),
					Metadata: &setupcfg.Metadata{VersionComparator: "==", DepGroup: "dev"},
				},
			},
		},
		{
			Name: "dynamic and indirect sources are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dynamic.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/dynamic.cfg", 14),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "pytest",
					Version:  "7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/dynamic.cfg", 19),
					Metadata: &setupcfg.Metadata{VersionComparator: ">=", DepGroup: "dev"},
				},
			},
		},
		{
			Name: "malformed entries are skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "valid-pkg",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/malformed.cfg", 6),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "good",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/malformed.cfg", 8),
					Metadata: &setupcfg.Metadata{VersionComparator: "=="},
				},
				{
					Name:     "ok-pkg",
					Version:  "1.2",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/malformed.cfg", 13),
					Metadata: &setupcfg.Metadata{VersionComparator: "~=", DepGroup: "dev"},
				},
			},
		},
		{
			Name: "unsupported single comparators emit name-only packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/unsupported-comparators.cfg",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "stevedore",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/unsupported-comparators.cfg", 3),
					Metadata: &setupcfg.Metadata{},
				},
				{
					Name:     "netaddr",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/unsupported-comparators.cfg", 4),
					Metadata: &setupcfg.Metadata{},
				},
			},
		},
		{
			Name: "no dependency sections yields no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.cfg",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()

			e, err := setupcfg.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("setupcfg.New() error: %v", err)
			}
			e.(*setupcfg.Extractor).Stats = collector

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
