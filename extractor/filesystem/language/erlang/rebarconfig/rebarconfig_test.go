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

package rebarconfig_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/rebarconfig"
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
			name:         "rebar.config in root",
			path:         "rebar.config",
			wantRequired: true,
		},
		{
			name:         "rebar.config in project",
			path:         "myproject/rebar.config",
			wantRequired: true,
		},
		{
			name:         "not rebar.config",
			path:         "myproject/rebar.config.txt",
			wantRequired: false,
		},
		{
			name:         "rebar.lock",
			path:         "myproject/rebar.lock",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/rebar.config/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := rebarconfig.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("rebarconfig.New() error: %v", err)
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
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 2),
				},
				{
					Name:     "jsx",
					Version:  "3.1.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/basic", 3),
				},
			},
		},
		{
			Name: "single line deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single_line",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/single_line", 1),
				},
				{
					Name:     "jsx",
					Version:  "3.1.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/single_line", 1),
				},
			},
		},
		{
			Name: "single quotes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/single_quotes",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/single_quotes", 2),
				},
			},
		},
		{
			Name: "git deps skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/git_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "jsx",
					Version:  "3.1.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/git_skipped", 2),
				},
			},
		},
		{
			Name: "complex forms skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/complex_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/complex_skipped", 2),
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
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/comments", 3),
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
			Name: "profiles skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/profiles_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "cowboy",
					Version:  "2.9.0",
					PURLType: purl.TypeHex,
					Location: extractor.LocationFromPathAndLine("testdata/profiles_skipped", 2),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := rebarconfig.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("rebarconfig.New() error: %v", err)
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
