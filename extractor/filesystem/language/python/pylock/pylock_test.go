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
	"github.com/google/osv-scalibr/testing/extracttest"
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
			e := pylock.Extractor{}
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
					Locations: []string{"testdata/example.toml"},
				},
				{
					Name:      "cattrs",
					Version:   "24.1.2",
					Locations: []string{"testdata/example.toml"},
				},
				{
					Name:      "numpy",
					Version:   "2.2.3",
					Locations: []string{"testdata/example.toml"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pylock.Extractor{}

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
