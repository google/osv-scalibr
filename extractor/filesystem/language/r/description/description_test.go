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

package description_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/description"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "DESCRIPTION in root",
			path:         "DESCRIPTION",
			wantRequired: true,
		},
		{
			name:         "DESCRIPTION in project",
			path:         "myproject/DESCRIPTION",
			wantRequired: true,
		},
		{
			name:         "not DESCRIPTION",
			path:         "myproject/DESCRIPTION.txt",
			wantRequired: false,
		},
		{
			name:         "renv.lock",
			path:         "myproject/renv.lock",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/DESCRIPTION/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := description.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("description.New() error: %v", err)
			}
			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: 1000,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "basic deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/basic"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"depends"}},
				},
				{
					Name:     "dplyr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/basic"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
				{
					Name:     "tidyr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/basic"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
			},
		},
		{
			Name: "multiple fields",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_fields",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiple_fields"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
				{
					Name:     "testthat",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiple_fields"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"suggests"}},
				},
				{
					Name:     "data.table",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiple_fields"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"enhances"}},
				},
				{
					Name:     "Rcpp",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiple_fields"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"linkingto"}},
				},
			},
		},
		{
			Name: "multiline fields",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiline",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiline"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"depends"}},
				},
				{
					Name:     "dplyr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiline"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"depends"}},
				},
				{
					Name:     "tidyr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiline"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"depends"}},
				},
				{
					Name:     "stringr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/multiline"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
			},
		},
		{
			Name: "version constraints",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/version_constraints",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/version_constraints"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
				{
					Name:     "dplyr",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/version_constraints"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"imports"}},
				},
				{
					Name:     "testthat",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/version_constraints"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"suggests"}},
				},
			},
		},
		{
			Name: "skip R dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/skip_r",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "ggplot2",
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath("testdata/skip_r"),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"depends"}},
				},
			},
		},
		{
			Name: "no deps",
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
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := description.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("description.New() error: %v", err)
			}
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
