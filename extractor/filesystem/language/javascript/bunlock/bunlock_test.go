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

package bunlock_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
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
			inputPath: "bun.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock",
			want:      true,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock/file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path/to/my/bun.lock.file",
			want:      false,
		},
		{
			name:      "",
			inputPath: "path.to.my.bun.lock",
			want:      false,
		},
		{
			name:      "",
			inputPath: "foo/node_modules/bar/bun.lock",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := bunlock.Extractor{}
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
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
			WantInventory: nil,
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json5",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json5",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/one-package.json5"},
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
				Path: "testdata/one-package-dev.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/one-package-dev.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package with bad tuple (first error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bad-tuple.json5",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad1' from"},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/bad-tuple.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "one package with bad tuple (second error)",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bad-tuple.json5",
			},
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad2' from"},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/bad-tuple.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"testdata/two-packages.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/two-packages.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "same package in different groups",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/same-package-different-groups.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					Locations:  []string{"testdata/same-package-different-groups.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"testdata/same-package-different-groups.json5"},
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
				Path: "testdata/scoped-packages.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@typescript-eslint/types",
					Version:    "5.62.0",
					Locations:  []string{"testdata/scoped-packages.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "scoped packages mixed",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages-mixed.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@babel/code-frame",
					Version:    "7.26.2",
					Locations:  []string{"testdata/scoped-packages-mixed.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					Version:    "7.25.9",
					Locations:  []string{"testdata/scoped-packages-mixed.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "js-tokens",
					Version:    "4.0.0",
					Locations:  []string{"testdata/scoped-packages-mixed.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "picocolors",
					Version:    "1.1.1",
					Locations:  []string{"testdata/scoped-packages-mixed.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					Version:    "1.0.2",
					Locations:  []string{"testdata/scoped-packages-mixed.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "optional package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/optional-package.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn",
					Version:    "8.14.0",
					Locations:  []string{"testdata/optional-package.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "fsevents",
					Version:    "0.3.8",
					Locations:  []string{"testdata/optional-package.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "nan",
					Version:    "2.22.0",
					Locations:  []string{"testdata/optional-package.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies implicit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-implicit.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"testdata/peer-dependencies-implicit.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.14.0",
					Locations:  []string{"testdata/peer-dependencies-implicit.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "peer dependencies explicit",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/peer-dependencies-explicit.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "acorn-jsx",
					Version:    "5.3.2",
					Locations:  []string{"testdata/peer-dependencies-explicit.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					Version:    "8.14.0",
					Locations:  []string{"testdata/peer-dependencies-explicit.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "ansi-styles",
					Version:    "4.3.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					Version:    "4.1.2",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					Version:    "2.0.1",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					Version:    "1.1.4",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "2.0.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "5.5.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"testdata/nested-dependencies.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "nested dependencies with duplicate versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/nested-dependencies-dup.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "ansi-styles",
					Version:    "4.3.0",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					Version:    "4.1.2",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					Version:    "2.0.1",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					Version:    "1.1.4",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "2.0.0",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"testdata/nested-dependencies-dup.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "alias",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/alias.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "has-flag",
					Version:    "4.0.0",
					Locations:  []string{"testdata/alias.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "7.2.0",
					Locations:  []string{"testdata/alias.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					Version:    "6.1.0",
					Locations:  []string{"testdata/alias.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					Version:    "3.0.0",
					Locations:  []string{"testdata/alias.json5"},
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
				Path: "testdata/commits.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "@babel/helper-plugin-utils",
					Version:    "7.26.5",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-string-parser",
					Version:    "7.25.9",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					Version:    "7.25.9",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/parser",
					Version:    "7.26.5",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/types",
					Version:    "7.26.5",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@prettier/sync",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "527e8ce",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1ae6dc1267500360b411ec711b8aeac8c68b2246",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98e8ff1",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac058",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "b7aef34",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jquery",
					Version:    "3.7.1",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					Version:    "1.3.1",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "make-synchronized",
					Version:    "0.2.9",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "php-parser",
					Version:    "2.2.0",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "prettier",
					Version:    "3.4.2",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "raven-js",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "91ef2d4",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "slick-carousel",
					Version:   "",
					Locations: []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fc6f7d8",
					},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "stopwords",
					Version:    "0.0.1",
					Locations:  []string{"testdata/commits.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:       "etag",
					Version:    "",
					Locations:  []string{"testdata/files.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					Version:    "1.3.1",
					Locations:  []string{"testdata/files.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "sample from blog post",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/blog-sample.json5",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "uWebSockets.js",
					Version:   "",
					Locations: []string{"testdata/blog-sample.json5"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6609a88",
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
			extr := bunlock.Extractor{}

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
