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

package cpanfile_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/perl/cpanfile"
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
			name:         "cpanfile in root",
			path:         "cpanfile",
			wantRequired: true,
		},
		{
			name:         "cpanfile in project",
			path:         "myproject/cpanfile",
			wantRequired: true,
		},
		{
			name:         "not cpanfile",
			path:         "myproject/cpanfile.txt",
			wantRequired: false,
		},
		{
			name:         "META.json",
			path:         "myproject/META.json",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/cpanfile/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cpanfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cpanfile.New() error: %v", err)
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
			Name: "basic requires",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 1),
				},
				{
					Name:     "DBI",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 2),
				},
			},
		},
		{
			Name: "requires with versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with_versions",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					Version:  ">= 2.00",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/with_versions", 1),
				},
				{
					Name:     "DBI",
					Version:  "== 1.643",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/with_versions", 2),
				},
				{
					Name:     "Try::Tiny",
					Version:  "~> 0.30",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/with_versions", 3),
				},
			},
		},
		{
			Name: "dependency groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dependency_groups",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/dependency_groups", 1),
				},
				{
					Name:     "Test::More",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/dependency_groups", 2),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"test"}},
				},
				{
					Name:     "Module::Build",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/dependency_groups", 3),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"configure"}},
				},
				{
					Name:     "ExtUtils::MakeMaker",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/dependency_groups", 4),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"build"}},
				},
			},
		},
		{
			Name: "recommends and suggests",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/recommends_suggests",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/recommends_suggests", 1),
				},
				{
					Name:     "Class::Load",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/recommends_suggests", 2),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"recommends"}},
				},
				{
					Name:     "Data::Dumper",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/recommends_suggests", 3),
					Metadata: &osv.DepGroupMetadata{DepGroupVals: []string{"suggests"}},
				},
			},
		},
		{
			Name: "blocks skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/blocks_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/blocks_skipped", 1),
				},
				{
					Name:     "DBI",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/blocks_skipped", 11),
				},
			},
		},
		{
			Name: "comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/comments", 4),
				},
				{
					Name:     "DBI",
					Version:  ">= 1.643",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/comments", 5),
				},
			},
		},
		{
			Name: "double quotes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/double_quotes",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					Version:  ">= 2.00",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/double_quotes", 1),
				},
				{
					Name:     "DBI",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/double_quotes", 2),
				},
			},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "dynamic constructs skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dynamic_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "Moose",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/dynamic_skipped", 1),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := cpanfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cpanfile.New() error: %v", err)
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
