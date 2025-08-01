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

package composerlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
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
			name:      "empty name",
			inputPath: "",
			want:      false,
		},
		{
			name:      "composer.lock from root",
			inputPath: "composer.lock",
			want:      true,
		},
		{
			name:      "composer.lock from subpath",
			inputPath: "path/to/my/composer.lock",
			want:      true,
		},
		{
			name:      "composer.lock as a dir",
			inputPath: "path/to/my/composer.lock/file",
			want:      false,
		},
		{
			name:      "composer.lock with additional extension",
			inputPath: "path/to/my/composer.lock.file",
			want:      false,
		},
		{
			name:      "composer.lock as substring",
			inputPath: "path.to.my.composer.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := composerlock.Extractor{}
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
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json",
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
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/one-package.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/one-package-dev.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
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
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/two-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "two packages alt",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages-alt.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "sentry/sdk",
					Version:   "2.0.4",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4c115873c86ad5bd0ac6d962db70ca53bf8fb874",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/two-packages-alt.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "drupal_packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/drupal-packages.json",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "drupal/core",
					Version:   "10.4.5",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/drupal-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5247dbaa65b42b601058555f4a8b2bd541f5611f",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "drupal/tfa",
					Version:   "2.0.0-alpha4",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/drupal-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "drupal/field_time",
					Version:   "1.0.0-beta5",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/drupal-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
				{
					Name:      "theseer/tokenizer",
					Version:   "1.1.3",
					PURLType:  purl.TypeComposer,
					Locations: []string{"testdata/drupal-packages.json"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "11336f6f84e16a720dae9d8e6ed5019efa85a0f9",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := composerlock.Extractor{}

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
