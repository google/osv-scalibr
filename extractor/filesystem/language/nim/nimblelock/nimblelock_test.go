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

package nimblelock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/nim/nimblelock"
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
			name:      "empty name",
			inputPath: "",
			want:      false,
		},
		{
			name:      "nimble.lock from root",
			inputPath: "nimble.lock",
			want:      true,
		},
		{
			name:      "nimble.lock from subpath",
			inputPath: "path/to/my/nimble.lock",
			want:      true,
		},
		{
			name:      "nimble.lock as a dir",
			inputPath: "path/to/my/nimble.lock/file",
			want:      false,
		},
		{
			name:      "nimble.lock with additional extension",
			inputPath: "path/to/my/nimble.lock.file",
			want:      false,
		},
		{
			name:      "nimble.lock as substring",
			inputPath: "path.to.my.nimble.lock",
			want:      false,
		},
		{
			name:      "other file",
			inputPath: "path/to/my/package.json",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := nimblelock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("nimblelock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "null json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/null.jsontest",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "empty packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages field",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "nimcrypto",
					Version:  "0.5.4",
					PURLType: purl.TypeNim,
					Location: extractor.LocationFromPath("testdata/one-package.json"),
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "nimcrypto",
					Version:  "0.5.4",
					PURLType: purl.TypeNim,
					Location: extractor.LocationFromPath("testdata/two-packages.json"),
				},
				{
					Name:     "unicodedb",
					Version:  "0.12.0",
					PURLType: purl.TypeNim,
					Location: extractor.LocationFromPath("testdata/two-packages.json"),
				},
			},
		},
		{
			Name: "missing version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-version.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "nimcrypto",
					Version:  "0.5.4",
					PURLType: purl.TypeNim,
					Location: extractor.LocationFromPath("testdata/missing-version.json"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := nimblelock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("nimblelock.New: %v", err)
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
