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

package condalock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condalock"
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
			name:      "empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "conda.lock",
			inputPath: "conda.lock",
			want:      true,
		},
		{
			name:      "conda-linux-64.lock",
			inputPath: "conda-linux-64.lock",
			want:      true,
		},
		{
			name:      "conda-osx-arm64.lock",
			inputPath: "conda-osx-arm64.lock",
			want:      true,
		},
		{
			name:      "path/to/conda.lock",
			inputPath: "path/to/conda.lock",
			want:      true,
		},
		{
			name:      "path/to/conda-win-64.lock",
			inputPath: "path/to/conda-win-64.lock",
			want:      true,
		},
		{
			name:      "not a lockfile",
			inputPath: "notconda.lock",
			want:      false,
		},
		{
			name:      "conda.lock as directory",
			inputPath: "path/to/conda.lock/file",
			want:      false,
		},
		{
			name:      "conda.lock with extra suffix",
			inputPath: "path/to/conda.lock.backup",
			want:      false,
		},
		{
			name:      "inside node_modules",
			inputPath: "node_modules/conda.lock",
			want:      false,
		},
		{
			name:      "nested inside node_modules",
			inputPath: "foo/node_modules/bar/conda.lock",
			want:      false,
		},
		{
			name:      "inside .git",
			inputPath: ".git/conda.lock",
			want:      false,
		},
		{
			name:      "nested inside .git",
			inputPath: "foo/.git/conda.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := condalock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("condalock.New: %v", err)
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
			Name: "valid lockfile with three packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/conda-linux-64.lock",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "python",
					Version:  "3.9.7",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPathAndLine("testdata/conda-linux-64.lock", 3),
				},
				{
					Name:     "numpy",
					Version:  "1.21.0",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPathAndLine("testdata/conda-linux-64.lock", 4),
				},
				{
					Name:     "libgcc-ng",
					Version:  "11.2.0",
					PURLType: purl.TypeConda,
					Location: extractor.LocationFromPathAndLine("testdata/conda-linux-64.lock", 5),
				},
			},
		},
		{
			Name: "empty file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "comments only",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/comments_only.lock",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "invalid URL",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-url.lock",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "invalid URL"},
			WantPackages: nil,
		},
		{
			Name: "no version in filename",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-version.lock",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not find version"},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := condalock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("condalock.New: %v", err)
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

func TestExtractor_Extract_conda_lock(t *testing.T) {
	extr, err := condalock.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("condalock.New: %v", err)
	}

	scanInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/conda.lock",
	})
	defer extracttest.CloseTestScanInput(t, scanInput)

	got, err := extr.Extract(t.Context(), &scanInput)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}

	want := inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:     "six",
			Version:  "1.16.0",
			PURLType: purl.TypeConda,
			Location: extractor.LocationFromPathAndLine("testdata/conda.lock", 2),
		},
	}}

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
		t.Errorf("Extract diff (-want +got):\n%s", diff)
	}
}
