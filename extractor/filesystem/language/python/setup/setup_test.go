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

// Copyright 2024 Google LLC
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

package setup_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     setup.Config
		wantCfg setup.Config
	}{
		{
			name: "default",
			cfg:  setup.DefaultConfig(),
			wantCfg: setup.Config{
				MaxFileSizeBytes: 10 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: setup.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: setup.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := setup.New(tt.cfg)
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
			name:             "setup.py file",
			path:             "software-develop/setup.py",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.py file required if file size < max file size",
			path:             "software-develop/setup.py",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.py file required if file size == max file size",
			path:             "software-develop/setup.py",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "setup.py file not required if file size > max file size",
			path:             "software-develop/setup.py",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "setup.py file required if max file size set to 0",
			path:             "software-develop/setup.py",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "invalid",
			path:         "software-develop/setup.py/foo",
			wantRequired: false,
		},
		{
			name:         "invalid",
			path:         "software-develop/foo/foosetup.py",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = setup.New(setup.Config{
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
			Name: "valid setup.py file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "pysaml2",
					Version:   "6.5.1",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "xmlschema",
					Version:   "1.7.1",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "requests",
					Version:   "2.25.1",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "lxml",
					Version:   "4.6.2",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "Jinja2",
					Version:   "2.11.3",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "pkg1",
					Version:   "0.1.1",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "pkg2",
					Version:   "0.1.2",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "foo",
					Version:   "2.20",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "pydantic",
					Version:   "1.8.2",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "certifi",
					Version:   "2017.4.17",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "pkg3",
					Version:   "1.2.3",
					Locations: []string{"testdata/valid"},
					Metadata:  &setup.Metadata{VersionComparator: "<="},
				},
			},
		},
		{
			Name: "valid setup.py file 2",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid_2",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "accelerate",
					Version:   "0.26.1",
					Locations: []string{"testdata/valid_2"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "transformers",
					Version:   "4.37.2",
					Locations: []string{"testdata/valid_2"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "datasets",
					Version:   "2.16.1",
					Locations: []string{"testdata/valid_2"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "mteb",
					Version:   "1.4.0",
					Locations: []string{"testdata/valid_2"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
			},
		},
		{
			Name: "valid setup.py file 3",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid_3",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "nanoplotter",
					Version:   "0.13.1",
					Locations: []string{"testdata/valid_3"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "nanoget",
					Version:   "0.11.0",
					Locations: []string{"testdata/valid_3"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "nanomath",
					Version:   "0.12.0",
					Locations: []string{"testdata/valid_3"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
			},
		},
		{
			Name: "template setup.py file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/template",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "requests",
					Version:   "2.25.1",
					Locations: []string{"testdata/template"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
				{
					Name:      "lxml",
					Version:   "4.6.2",
					Locations: []string{"testdata/template"},
					Metadata:  &setup.Metadata{VersionComparator: ">="},
				},
				{
					Name:      "Jinja2",
					Version:   "2.11.3",
					Locations: []string{"testdata/template"},
					Metadata:  &setup.Metadata{VersionComparator: "=="},
				},
			},
		},
		{
			Name: "empty package setup.py file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty_2",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()

			var e filesystem.Extractor = setup.New(setup.Config{
				Stats:            collector,
				MaxFileSizeBytes: 30,
			})

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(context.Background(), &scanInput)

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

func TestToPURL(t *testing.T) {
	e := setup.Extractor{}
	p := &extractor.Package{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypePyPi,
		Name:    "name",
		Version: "1.2.3",
	}
	got := e.ToPURL(p)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", p, diff)
	}
}
