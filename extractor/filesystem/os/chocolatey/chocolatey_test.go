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

package chocolatey_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey"
	chocolateymeta "github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		desc                  string
		path                  string
		fileSize              int64
		maxFileSize           int64
		pluginSpecificMaxSize int64
		want                  bool
	}{
		{
			desc: "nuspec file",
			path: "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			want: true,
		},
		{
			desc: "invalid file extension",
			path: "/ProgramData/chocolatey/lib/vscode/vscode.nuspecrandom",
			want: false,
		},
		{
			desc: "invalid folder",
			path: "/ProgramData/chocolatey/lib-bad/vscode/vscode.nuspec",
			want: false,
		},
		{
			desc: "invalid file",
			path: "/ProgramData/choco.exe",
			want: false,
		},
		{
			desc:        "file_size_below_limit",
			path:        "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSize:    1000,
			maxFileSize: 1000,
			want:        true,
		},
		{
			desc:        "file_size_above_limit",
			path:        "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSize:    1001,
			maxFileSize: 1000,
			want:        false,
		},
		{
			desc:                  "override_global_size_below_limit",
			path:                  "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSize:              1001,
			maxFileSize:           1000,
			pluginSpecificMaxSize: 1001,
			want:                  true,
		},
		{
			desc:                  "override_global_size_above_limit",
			path:                  "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSize:              1001,
			maxFileSize:           1001,
			pluginSpecificMaxSize: 1000,
			want:                  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			e, err := chocolatey.New(&cpb.PluginConfig{
				MaxFileSizeBytes: tt.maxFileSize,
				PluginSpecific: []*cpb.PluginSpecificConfig{
					{Config: &cpb.PluginSpecificConfig_Chocolatey{Chocolatey: &cpb.ChocolateyConfig{MaxFileSizeBytes: tt.pluginSpecificMaxSize}}},
				},
			})
			if err != nil {
				t.Fatalf("chocolatey.New(): %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileSize: tt.fileSize,
			})); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		inputConfig  extracttest.ScanInputMockConfig
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "valid nuspec file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/atom.nuspec",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "atom",
					Version:  "1.60.0",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "atom",
						Version:    "1.60.0",
						Authors:    "GitHub Inc.",
						LicenseURL: "https://github.com/atom/atom/blob/master/LICENSE.md",
						ProjectURL: "https://atom.io/",
						Tags:       "atom admin text editor notepad github package autocompletion",
					},
					Locations: []string{"testdata/atom.nuspec"},
				},
			},
		},
		{
			name: "valid nuspec file for install dependency",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/atom.install.nuspec",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "atom.install",
					Version:  "1.60.0",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "atom.install",
						Version:    "1.60.0",
						Authors:    "GitHub Inc.",
						LicenseURL: "https://github.com/atom/atom/blob/master/LICENSE.md",
						ProjectURL: "https://atom.io/",
						Tags:       "atom admin text editor notepad github package autocompletion",
					},
					Locations: []string{"testdata/atom.install.nuspec"},
				},
			},
		},
		{
			name: "missing tags field in a valid nuspec file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/cmake.nuspec",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "cmake",
					Version:  "4.1.1",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "cmake",
						Version:    "4.1.1",
						Authors:    "Andy Cedilnik, Bill Hoffman, Brad King, Ken Martin, Alexander Neundorf",
						LicenseURL: "https://gitlab.kitware.com/cmake/cmake/blob/master/Copyright.txt",
						ProjectURL: "https://www.cmake.org/",
						Tags:       "",
					},
					Locations: []string{"testdata/cmake.nuspec"},
				},
			},
		},
		{
			name: "missing id field in an invalid nuspec file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/atom_withoutid.nuspec",
			},
			wantPackages: []*extractor.Package{},
		},
		{
			name: "missing version field in a nuspec file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/atom_withoutversion.nuspec",
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "atom",
					Version:  "",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "atom",
						Authors:    "GitHub Inc.",
						LicenseURL: "https://github.com/atom/atom/blob/master/LICENSE.md",
						ProjectURL: "https://atom.io/",
						Tags:       "atom admin text editor notepad github package autocompletion",
					},
					Locations: []string{"testdata/atom_withoutversion.nuspec"},
				},
			},
		},
		{
			name: "invalid nuspec file",
			inputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.nuspec",
			},
			wantErr: extracttest.ContainsErrStr{Str: "error parsing nuspec"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := chocolatey.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.inputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfig.Path, diff)
			}
		})
	}
}
