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

package pyprojecttoml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pyprojecttoml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
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
			name:      "exact_match",
			inputPath: "pyproject.toml",
			want:      true,
		},
		{
			name:      "in_subdirectory",
			inputPath: "path/to/my/pyproject.toml",
			want:      true,
		},
		{
			name:      "not_pyproject_toml",
			inputPath: "setup.cfg",
			want:      false,
		},
		{
			name:      "pylock_toml",
			inputPath: "pylock.toml",
			want:      false,
		},
		{
			name:      "wrong_extension",
			inputPath: "pyproject.toml.bak",
			want:      false,
		},
		{
			name:      "pyproject_toml_as_directory",
			inputPath: "pyproject.toml/something",
			want:      false,
		},
		{
			name:      "uppercase",
			inputPath: "PYPROJECT.TOML",
			want:      false,
		},
		{
			name:      "requirements_txt",
			inputPath: "requirements.txt",
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pyprojecttoml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pyprojecttoml.New(): %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf(
					"FileRequired(%q) got = %v, want %v",
					tt.inputPath, got, tt.want,
				)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "simple_deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/simple_deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.32.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/simple_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "==",
						Requirement:       "requests==2.32.0",
					},
				},
				{
					Name:     "flask",
					Version:  "3.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/simple_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: ">=",
						Requirement:       "flask>=3.0.0",
					},
				},
				{
					Name:     "numpy",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/simple_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "",
						Requirement:       "numpy",
					},
				},
			},
		},
		{
			Name: "optional_deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional_deps.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.32.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/optional_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "==",
						Requirement:       "requests==2.32.0",
					},
				},
				{
					Name:     "pytest",
					Version:  "7.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/optional_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: ">=",
						Requirement:       "pytest>=7.0.0",
					},
				},
				{
					Name:     "black",
					Version:  "23.1.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/optional_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "==",
						Requirement:       "black==23.1.0",
					},
				},
				{
					Name:     "aiohttp",
					Version:  "3.8.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/optional_deps.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: ">=",
						Requirement:       "aiohttp>=3.8.0",
					},
				},
			},
		},
		{
			Name: "extras_syntax",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/extras_syntax.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "flask",
					Version:  "3.1.1",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/extras_syntax.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "==",
						Requirement:       "flask[async]==3.1.1",
					},
				},
				{
					Name:     "requests",
					Version:  "2.20.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/extras_syntax.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: ">=",
						Requirement:       "requests[security]>=2.20.0",
					},
				},
			},
		},
		{
			Name: "env_markers",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/env_markers.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.20.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/env_markers.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: ">=",
						Requirement: "requests>=2.20.0; python_version >= \"3.8\"",
					},
				},
				{
					Name:     "importlib-metadata",
					Version:  "6.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath(
						"testdata/env_markers.toml",
					),
					Metadata: &requirements.Metadata{
						VersionComparator: "==",
						Requirement: "importlib-metadata==6.0.0; python_version < \"3.10\"",
					},
				},
			},
		},
		{
			Name: "no_project_table",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no_project_table.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "dynamic_deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/dynamic_deps.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "empty_deps",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty_deps.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "malformed_toml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/malformed.toml",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := pyprojecttoml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pyprojecttoml.New(): %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(
				tt.WantErr, err, cmpopts.EquateErrors(),
			); diff != "" {
				t.Errorf(
					"%s.Extract(%q) error diff (-want +got):\n%s",
					e.Name(), tt.InputConfig.Path, diff,
				)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(
				wantInv, got,
				cmpopts.SortSlices(extracttest.PackageCmpLess),
			); diff != "" {
				t.Errorf(
					"%s.Extract(%q) diff (-want +got):\n%s",
					e.Name(), tt.InputConfig.Path, diff,
				)
			}
		})
	}
}
