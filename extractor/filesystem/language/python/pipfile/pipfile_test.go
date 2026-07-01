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

package pipfile_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfile"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		name      string
		inputPath string
		want      bool
	}{
		{
			name:      "empty",
			inputPath: "",
			want:      false,
		},
		{
			name:      "Pipfile",
			inputPath: "Pipfile",
			want:      true,
		},
		{
			name:      "path/to/Pipfile",
			inputPath: "path/to/my/Pipfile",
			want:      true,
		},
		{
			name:      "Pipfile/file",
			inputPath: "path/to/my/Pipfile/file",
			want:      false,
		},
		{
			name:      "Pipfile.lock",
			inputPath: "path/to/my/Pipfile.lock",
			want:      false,
		},
		{
			name:      "not Pipfile",
			inputPath: "path/to/my/package.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "toml.Unmarshal"},
			WantPackages: nil,
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-deps.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-dep.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/one-dep.toml"),
				},
			},
		},
		{
			Name: "multiple dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multi-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/multi-deps.toml"),
				},
				{
					Name:     "flask",
					Version:  "2.3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/multi-deps.toml"),
				},
				{
					Name:     "django",
					Version:  "4.2",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/multi-deps.toml"),
				},
			},
		},
		{
			Name: "dev packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dev-packages.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "pytest",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/dev-packages.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "black",
					Version:  "23.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/dev-packages.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "mixed deps and dev packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed-deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/mixed-deps.toml"),
				},
				{
					Name:     "flask",
					Version:  "2.3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/mixed-deps.toml"),
				},
				{
					Name:     "pytest",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/mixed-deps.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "black",
					Version:  "23.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/mixed-deps.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "skip git dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/skip-git.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/skip-git.toml"),
				},
			},
		},
		{
			Name: "skip path dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/skip-path.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/skip-path.toml"),
				},
			},
		},
		{
			Name: "table version specification",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/table-version.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/table-version.toml"),
				},
				{
					Name:     "flask",
					Version:  "2.3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/table-version.toml"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
