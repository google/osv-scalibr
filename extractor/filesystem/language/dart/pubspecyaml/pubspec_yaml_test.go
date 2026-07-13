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

package pubspecyaml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspecyaml"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
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
			name:      "pubspec.yaml at root",
			inputPath: "pubspec.yaml",
			want:      true,
		},
		{
			name:      "pubspec.yaml in nested directory",
			inputPath: "path/to/my/pubspec.yaml",
			want:      true,
		},
		{
			name:      "wrong file name",
			inputPath: "path/to/my/pubspec.yml",
			want:      false,
		},
		{
			name:      "lockfile not manifest",
			inputPath: "path/to/my/pubspec.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := pubspecyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pubspecyaml.New() error: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-yaml.txt",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-sdk.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "http",
					Version:  "^0.13.5",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/one-package.yaml"),
					Metadata: &osv.DepGroupMetadata{},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "build_runner",
					Version:  "^2.3.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/one-package-dev.yaml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "mixed packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/mixed-packages.yaml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "analyzer",
					Version:  "5.0.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{},
				},
				{
					Name:     "build_runner",
					Version:  "^2.3.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "dio",
					Version:  "5.0.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{},
				},
				{
					Name:     "http",
					Version:  "^0.13.5",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{},
				},
				{
					Name:     "mockito",
					Version:  ">=5.0.0 <6.0.0",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:     "path_provider",
					Version:  "2.0.15",
					PURLType: purl.TypePub,
					Location: extractor.LocationFromPath("testdata/mixed-packages.yaml"),
					Metadata: &osv.DepGroupMetadata{},
				},
			},
		},
		{
			Name: "package with git source",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/source-git.yaml",
			},
			WantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := pubspecyaml.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("pubspecyaml.New() error: %v", err)
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
