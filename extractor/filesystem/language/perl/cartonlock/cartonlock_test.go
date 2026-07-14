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

package cartonlock_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/perl/cartonlock"
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
			name:         "cpanfile.snapshot in root",
			path:         "cpanfile.snapshot",
			wantRequired: true,
		},
		{
			name:         "cpanfile.snapshot in project",
			path:         "myproject/cpanfile.snapshot",
			wantRequired: true,
		},
		{
			name:         "not cpanfile.snapshot",
			path:         "myproject/cpanfile.snapshot.txt",
			wantRequired: false,
		},
		{
			name:         "cpanfile",
			path:         "myproject/cpanfile",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/cpanfile.snapshot/foo",
			wantRequired: false,
		},
		{
			name:         "too large",
			path:         "myproject/cpanfile.snapshot",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cartonlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cartonlock.New() error: %v", err)
			}
			fileSize := int64(1000)
			if tt.name == "too large" {
				fileSize = 11 * 1024 * 1024
			}
			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSize,
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
			Name: "basic snapshot",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "CPAN::Meta::Requirements",
					Version:  "2.143",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 6),
				},
				{
					Name:     "CPAN::Meta::Requirements::Range",
					Version:  "2.143",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 7),
				},
				{
					Name:     "File::Slurp",
					Version:  "9999.32",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 19),
				},
				{
					Name:     "JSON::PP::Boolean",
					Version:  "1.01",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 37),
				},
				{
					Name:     "TOML",
					Version:  "0.96",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 28),
				},
				{
					Name:     "Types::Serialiser",
					Version:  "1.01",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 38),
				},
				{
					Name:     "Types::Serialiser::BooleanBase",
					Version:  "1.01",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 39),
				},
				{
					Name:     "Types::Serialiser::Error",
					Version:  "1.01",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 40),
				},
			},
		},
		{
			Name: "empty distributions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty_distributions",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "undef versions skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/undef_versions",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "TOML::Parser",
					Version:  "0.91",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/undef_versions", 12),
				},
				{
					Name:     "common::sense",
					Version:  "3.75",
					PURLType: purl.TypeCPAN,
					Location: extractor.LocationFromPathAndLine("testdata/undef_versions", 6),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := cartonlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cartonlock.New() error: %v", err)
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
