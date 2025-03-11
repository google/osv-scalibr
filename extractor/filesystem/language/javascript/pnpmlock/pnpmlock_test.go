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

package pnpmlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
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
			inputPath: "pnpm-lock.yaml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/pnpm-lock.yaml.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.pnpm-lock.yaml",
			want:      false,
		},
		{
			name:      "",
			inputPath: "foo/node_modules/bar/pnpn-lock.yaml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := pnpmlock.Extractor{}
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
			Name: "invalid yaml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-yaml.txt",
			},
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
			WantInventory: nil,
		},
		{
			Name: "invalid dep path",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-path.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path"},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/invalid-path.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "invalid dep paths (first error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-paths.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path: invalidpath1"},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/invalid-paths.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "invalid dep paths (second error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-paths.yaml",
			},
			WantErr: extracttest.ContainsErrStr{Str: "invalid dependency path: invalidpath2"},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/invalid-paths.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.yaml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.yaml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/one-package.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package v6 lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-v6-lockfile.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/one-package-v6-lockfile.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package dev",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package-dev.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/one-package-dev.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					Locations:  []string{"testdata/scoped-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages v6 lockfile",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages-v6-lockfile.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.57.1",
					Locations:  []string{"testdata/scoped-packages-v6-lockfile.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"testdata/peer-dependencies.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.7.0",
					Locations:  []string{"testdata/peer-dependencies.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies advanced",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-advanced.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@typescript-eslint/eslint-plugin",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/parser",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/type-utils",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/typescript-estree",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@typescript-eslint/utils",
					Version:    "5.13.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint-utils",
					Version:    "3.0.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "eslint",
					Version:    "8.10.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "tsutils",
					Version:    "3.21.0",
					Locations:  []string{"testdata/peer-dependencies-advanced.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-packages.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "aws-sdk",
					Version:    "2.1087.0",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "base64-js",
					Version:    "1.5.1",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "buffer",
					Version:    "4.9.2",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "events",
					Version:    "1.1.1",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ieee754",
					Version:    "1.1.13",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "isarray",
					Version:    "1.0.0",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jmespath",
					Version:    "0.16.0",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "punycode",
					Version:    "1.3.2",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "querystring",
					Version:    "0.2.0",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "sax",
					Version:    "1.2.1",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "url",
					Version:    "0.10.3",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "3.3.2",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xml2js",
					Version:    "0.4.19",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					Locations:  []string{"testdata/multiple-packages.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "uuid",
					Version:    "3.3.2",
					Locations:  []string{"testdata/multiple-versions.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "uuid",
					Version:    "8.3.2",
					Locations:  []string{"testdata/multiple-versions.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "xmlbuilder",
					Version:    "9.0.7",
					Locations:  []string{"testdata/multiple-versions.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "tarball",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/tarball.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@my-org/my-package",
					Version:    "3.2.3",
					Locations:  []string{"testdata/tarball.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{"dev"},
					},
				},
			},
		},
		{
			Name: "exotic",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/exotic.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "foo",
					Version:    "1.0.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.0.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.1.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@foo/bar",
					Version:    "1.1.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.2.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.3.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "foo",
					Version:    "1.4.0",
					Locations:  []string{"testdata/exotic.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "my-bitbucket-package",
					Version:   "1.0.0",
					Locations: []string{"testdata/commits.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6104ae42cd32c3d724036d3964678f197b2c9cdb",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@my-scope/my-package",
					Version:   "1.0.0",
					Locations: []string{"testdata/commits.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "267087851ad5fac92a184749c27cd539e2fc862e",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@my-scope/my-other-package",
					Version:   "1.0.0",
					Locations: []string{"testdata/commits.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fbfc962ab51eb1d754749b68c064460221fbd689",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "faker-parser",
					Version:   "0.0.1",
					Locations: []string{"testdata/commits.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d2dc42a9351d4d89ec48c525e34f612b6d77993f",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "mocks",
					Version:   "20.0.1",
					Locations: []string{"testdata/commits.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "590f321b4eb3f692bb211bd74e22947639a6f79d",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.yaml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "my-file-package",
					Version:    "0.0.0",
					Locations:  []string{"testdata/files.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-local-package",
					Version:    "1.0.0",
					Locations:  []string{"testdata/files.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "a-nested-local-package",
					Version:    "1.0.0",
					Locations:  []string{"testdata/files.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up",
					Version:    "1.0.0",
					Locations:  []string{"testdata/files.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "one-up-with-peer",
					Version:    "1.0.0",
					Locations:  []string{"testdata/files.yaml"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pnpmlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			if diff := cmp.Diff(tt.WantInventory, got, cmpopts.SortSlices(extracttest.InventoryCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
