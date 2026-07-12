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

package stackyaml_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stackyaml"
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
			name:         "stack.yaml in root",
			path:         "stack.yaml",
			wantRequired: true,
		},
		{
			name:         "stack.yaml in project",
			path:         "myproject/stack.yaml",
			wantRequired: true,
		},
		{
			name:         "not stack.yaml",
			path:         "myproject/stack.yaml.lock",
			wantRequired: false,
		},
		{
			name:         "stack.yaml.lock",
			path:         "myproject/stack.yaml.lock",
			wantRequired: false,
		},
		{
			name:         "invalid nested path",
			path:         "myproject/stack.yaml/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := stackyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("stackyaml.New() error: %v", err)
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
			Name: "basic extra-deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/basic",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "acme-missiles",
					Version:  "0.3",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
				{
					Name:     "github",
					Version:  "0.15",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/basic"),
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_versions",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "lens",
					Version:  "4.19.2",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiple_versions"),
				},
				{
					Name:     "aeson",
					Version:  "1.5.6.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiple_versions"),
				},
				{
					Name:     "text",
					Version:  "1.2.5.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/multiple_versions"),
				},
			},
		},
		{
			Name: "no version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_version",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "some-package",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/no_version"),
				},
			},
		},
		{
			Name: "github and git deps skipped",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/github_git_skipped",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "github",
					Version:  "0.15",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/github_git_skipped"),
				},
				{
					Name:     "normal-pkg",
					Version:  "1.0.0",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/github_git_skipped"),
				},
			},
		},
		{
			Name: "empty list",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty_list",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no extra-deps field",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_extra_deps",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "acme-missiles",
					Version:  "0.3",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/comments"),
				},
			},
		},
		{
			Name: "prerelease versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/prerelease_versions",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "my-prerelease",
					Version:  "1.0.0-beta",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/prerelease_versions"),
				},
				{
					Name:     "my-prerelease",
					Version:  "1.0.0-alpha",
					PURLType: purl.TypeHaskell,
					Location: extractor.LocationFromPath("testdata/prerelease_versions"),
				},
			},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty_file",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid_yaml",
			},
			WantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := stackyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("stackyaml.New() error: %v", err)
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
