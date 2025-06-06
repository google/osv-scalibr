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

package uvlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func pkg(t *testing.T, name string, version string, location string) *extractor.Package {
	t.Helper()

	return &extractor.Package{
		Name:      name,
		Version:   version,
		PURLType:  purl.TypePyPi,
		Locations: []string{location},
		Metadata: osv.DepGroupMetadata{
			DepGroupVals: []string{},
		},
	}
}

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
			inputPath: "uv.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/uv.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/uv.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/uv.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.uv.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := uvlock.Extractor{}
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
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract from"},
			WantPackages: nil,
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.lock",
			},
			WantPackages: []*extractor.Package{
				pkg(t, "emoji", "2.14.0", "testdata/one-package.lock"),
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.lock",
			},
			WantPackages: []*extractor.Package{
				pkg(t, "emoji", "2.14.0", "testdata/two-packages.lock"),
				pkg(t, "protobuf", "4.25.5", "testdata/two-packages.lock"),
			},
		},
		{
			Name: "source git",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-git.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "ruff",
					Version:   "0.8.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/source-git.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "84748be16341b76e073d117329f7f5f4ee2941ad",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "grouped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/grouped-packages.lock",
			},
			WantPackages: []*extractor.Package{
				pkg(t, "emoji", "2.14.0", "testdata/grouped-packages.lock"),
				{
					Name:      "click",
					Version:   "8.1.7",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/grouped-packages.lock"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"cli"},
					},
				},
				pkg(t, "colorama", "0.4.6", "testdata/grouped-packages.lock"),
				{
					Name:      "black",
					Version:   "24.10.0",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/grouped-packages.lock"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev", "test"},
					},
				},
				{
					Name:      "flake8",
					Version:   "7.1.1",
					PURLType:  purl.TypePyPi,
					Locations: []string{"testdata/grouped-packages.lock"},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"test"},
					},
				},
				pkg(t, "mccabe", "0.7.0", "testdata/grouped-packages.lock"),
				pkg(t, "mypy-extensions", "1.0.0", "testdata/grouped-packages.lock"),
				pkg(t, "packaging", "24.2", "testdata/grouped-packages.lock"),
				pkg(t, "pathspec", "0.12.1", "testdata/grouped-packages.lock"),
				pkg(t, "platformdirs", "4.3.6", "testdata/grouped-packages.lock"),
				pkg(t, "pycodestyle", "2.12.1", "testdata/grouped-packages.lock"),
				pkg(t, "pyflakes", "3.2.0", "testdata/grouped-packages.lock"),
				pkg(t, "tomli", "2.2.1", "testdata/grouped-packages.lock"),
				pkg(t, "typing-extensions", "4.12.2", "testdata/grouped-packages.lock"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := uvlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

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
