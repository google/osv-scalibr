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

package cabalfile_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabalfile"
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
			name:         "mypackage.cabal in root",
			path:         "mypackage.cabal",
			wantRequired: true,
		},
		{
			name:         "mypackage.cabal in project",
			path:         "myproject/mypackage.cabal",
			wantRequired: true,
		},
		{
			name:         "not .cabal",
			path:         "myproject/mypackage.txt",
			wantRequired: false,
		},
		{
			name:         "cabal.project.freeze",
			path:         "myproject/cabal.project.freeze",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/mypackage.cabal/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cabalfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cabalfile.New() error: %v", err)
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
			Name: "basic build-depends",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "aeson",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
			},
		},
		{
			Name: "library section",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/library_section",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "text",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/library_section"),
				},
				{
					Name:     "bytestring",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/library_section"),
				},
			},
		},
		{
			Name: "executable and test suite",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/executable_test",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "optparse-applicative",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/executable_test"),
				},
				{
					Name:     "tasty",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/executable_test"),
				},
				{
					Name:     "tasty-hunit",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/executable_test"),
				},
			},
		},
		{
			Name: "multiline build-depends",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiline",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "base",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiline"),
				},
				{
					Name:     "aeson",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiline"),
				},
				{
					Name:     "text",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiline"),
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
					Name:     "base",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/comments"),
				},
			},
		},
		{
			Name: "no build-depends",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_build_depends",
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
			e, err := cabalfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("cabalfile.New() error: %v", err)
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
