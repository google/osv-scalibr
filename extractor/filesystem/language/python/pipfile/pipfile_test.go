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
			name:      "Empty path",
			inputPath: "",
			want:      false,
		},
		{
			name:      "Just Pipfile",
			inputPath: "Pipfile",
			want:      true,
		},
		{
			name:      "Nested Pipfile",
			inputPath: "path/to/my/Pipfile",
			want:      true,
		},
		{
			name:      "Pipfile.lock should be ignored",
			inputPath: "path/to/my/Pipfile.lock",
			want:      false,
		},
		{
			name:      "Not a Pipfile",
			inputPath: "path/to/my/otherfile",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New(): %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.inputPath, nil)); got != tt.want {
				t.Errorf("FileRequired(%s) = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid Pipfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "anyio",
					Version:  "4.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "black",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "django",
					Version:  "4.2.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "flask",
					Version:  "",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "pytest",
					Version:  "7.4.3",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "requests",
					Version:  "2.31.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "urllib3",
					Version:  "2.0.7",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPath("testdata/valid.toml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "empty Pipfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid Pipfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.toml",
			},
			WantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := pipfile.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pipfile.New(): %v", err)
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
