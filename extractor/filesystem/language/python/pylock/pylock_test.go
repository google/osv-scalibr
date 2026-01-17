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

package pylock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pylock"
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
			name:      "",
			inputPath: "",
			want:      false,
		},
		{
			name:      "",
			inputPath: "mypylock.toml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "pylock.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "pylock.spam.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "pylock.beans.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "PYLOCK.spam.toml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/pylock.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pylock.spam.toml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pylock.toml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/pylock.toml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.pylock.toml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pylock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pylock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
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
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "example",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/example.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "attrs",
					Version:   "25.1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/example.toml"},
				},
				{
					Name:      "cattrs",
					Version:   "24.1.2",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/example.toml"},
				},
				{
					Name:      "numpy",
					Version:   "2.2.3",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/example.toml"},
				},
			},
		},
		{
			Name: "package_with_commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "click",
					Version:   "8.2.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
				{
					Name:      "mleroc",
					Version:   "0.1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "735093f03c4d8be70bfaaae44074ac92d7419b6d",
					},
				},
				{
					Name:      "packaging",
					Version:   "24.2",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
				{
					Name:      "pathspec",
					Version:   "0.12.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
				{
					Name:      "python-dateutil",
					Version:   "2.9.0.post0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
				{
					Name:      "scikit-learn",
					Version:   "1.6.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
				{
					Name:      "tqdm",
					Version:   "4.67.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/commits.toml"},
				},
			},
		},
		{
			Name: "created_by_pip_with_just_self",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/pip-just-self.toml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "created_by_pip",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/pip-full.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "annotated-types",
					Version:   "0.7.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pip-full.toml"},
				},
				{
					Name:      "packaging",
					Version:   "25.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pip-full.toml"},
				},
				{
					Name:      "pyproject-toml",
					Version:   "0.1.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pip-full.toml"},
				},
				{
					Name:      "setuptools",
					Version:   "80.9.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pip-full.toml"},
				},
				{
					Name:      "wheel",
					Version:   "0.45.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pip-full.toml"},
				},
			},
		},
		{
			Name: "created_by_pdm",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/pdm-full.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "certifi",
					Version:   "2025.1.31",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "chardet",
					Version:   "3.0.4",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "charset-normalizer",
					Version:   "2.0.12",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "colorama",
					Version:   "0.3.9",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "idna",
					Version:   "2.7",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "py",
					Version:   "1.4.34",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "pytest",
					Version:   "3.2.5",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "requests",
					Version:   "2.27.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "setuptools",
					Version:   "39.2.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
				{
					Name:      "urllib3",
					Version:   "1.26.20",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/pdm-full.toml"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := pylock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pylock.New: %v", err)
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
