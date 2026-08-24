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

package bunlock_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
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
			e, err := bunlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("bunlock.New: %v", err)
			}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s, FileInfo) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

// testIDGenerator produces IDs unique across duplicate package names, unlike
// mockidgenerator, and resettable per subtest, unlike SequentialIDGenerator.
type testIDGenerator struct{ counter int }

func (g *testIDGenerator) GenerateID(name string) (string, error) {
	g.counter++
	return fmt.Sprintf("id-%s-%d", name, g.counter), nil
}

func TestExtractor_Extract(t *testing.T) {
	loc := extractor.LocationFromPathAndLine
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid json",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-json.txt",
			},
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
			WantPackages: nil,
		},
		{
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.json5",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-packages.json5",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					ID:         "id-wrappy-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/one-package.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					ID:         "id-wrappy-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/one-package-dev.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad1'"},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					ID:         "id-wrappy-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/bad-tuple.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantErr: extracttest.ContainsErrStr{Str: "could not extract 'wrappy-bad2'"},
			WantPackages: []*extractor.Package{
				{
					Name:       "wrappy",
					ID:         "id-wrappy-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/bad-tuple.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					ID:         "id-has-flag-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/two-packages.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					ID:         "id-wrappy-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/two-packages.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					ID:         "id-has-flag-1",
					ParentIDs:  map[string]bool{"root": true, "id-supports-color-2": true},
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/same-package-different-groups.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/same-package-different-groups.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "@typescript-eslint/types",
					ID:         "id-@typescript-eslint/types-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "5.62.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "@babel/code-frame",
					ID:         "id-@babel/code-frame-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "7.26.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					ID:         "id-@babel/helper-validator-identifier-2",
					ParentIDs:  map[string]bool{"id-@babel/code-frame-1": true},
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "js-tokens",
					ID:         "id-js-tokens-3",
					ParentIDs:  map[string]bool{"id-@babel/code-frame-1": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "picocolors",
					ID:         "id-picocolors-4",
					ParentIDs:  map[string]bool{"id-@babel/code-frame-1": true},
					Version:    "1.1.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 21),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					ID:         "id-wrappy-5",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/scoped-packages-mixed.json5", 23),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn",
					ID:         "id-acorn-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "fsevents",
					ID:         "id-fsevents-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "0.3.8",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "nan",
					ID:         "id-nan-3",
					ParentIDs:  map[string]bool{"id-fsevents-2": true},
					Version:    "2.22.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/optional-package.json5", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					ID:         "id-acorn-jsx-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-implicit.json5", 14),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					ID:         "id-acorn-1",
					ParentIDs:  map[string]bool{"id-acorn-jsx-2": true},
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-implicit.json5", 12),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "acorn-jsx",
					ID:         "id-acorn-jsx-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "5.3.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-explicit.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "acorn",
					ID:         "id-acorn-1",
					ParentIDs:  map[string]bool{"root": true, "id-acorn-jsx-2": true},
					Version:    "8.14.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/peer-dependencies-explicit.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "ansi-styles",
					ID:         "id-ansi-styles-1",
					ParentIDs:  map[string]bool{"id-chalk-2": true},
					Version:    "4.3.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					ID:         "id-chalk-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "4.1.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					ID:         "id-color-convert-5",
					ParentIDs:  map[string]bool{"id-ansi-styles-1": true},
					Version:    "2.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					ID:         "id-color-name-6",
					ParentIDs:  map[string]bool{"id-color-convert-5": true},
					Version:    "1.1.4",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-7",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "2.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-8",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "5.5.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-3",
					ParentIDs:  map[string]bool{"id-chalk-2": true},
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-9",
					ParentIDs:  map[string]bool{"id-supports-color-8": true},
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-4",
					ParentIDs:  map[string]bool{"id-supports-color-3": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies.json5", 32),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "ansi-styles",
					ID:         "id-ansi-styles-1",
					ParentIDs:  map[string]bool{"id-chalk-2": true},
					Version:    "4.3.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 16),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "chalk",
					ID:         "id-chalk-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "4.1.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 18),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-convert",
					ID:         "id-color-convert-3",
					ParentIDs:  map[string]bool{"id-ansi-styles-1": true},
					Version:    "2.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 20),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "color-name",
					ID:         "id-color-name-4",
					ParentIDs:  map[string]bool{"id-color-convert-3": true},
					Version:    "1.1.4",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-5",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "2.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-6",
					ParentIDs:  map[string]bool{"root": true, "id-chalk-2": true},
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-7",
					ParentIDs:  map[string]bool{"id-supports-color-6": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/nested-dependencies-dup.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					ID:         "id-has-flag-1",
					ParentIDs:  map[string]bool{"id-supports-color-2": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 13),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-3",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "6.1.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "has-flag",
					ID:         "id-has-flag-4",
					ParentIDs:  map[string]bool{"id-supports-color-3": true},
					Version:    "3.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/alias.json5", 19),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "@babel/helper-plugin-utils",
					ID:         "id-@babel/helper-plugin-utils-1",
					ParentIDs:  map[string]bool{"id-babel-preset-php-7": true},
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 22),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-string-parser",
					ID:         "id-@babel/helper-string-parser-2",
					ParentIDs:  map[string]bool{"id-@babel/types-5": true},
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 24),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/helper-validator-identifier",
					ID:         "id-@babel/helper-validator-identifier-3",
					ParentIDs:  map[string]bool{"id-@babel/types-5": true},
					Version:    "7.25.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/parser",
					ID:         "id-@babel/parser-4",
					ParentIDs:  map[string]bool{"id-babel-preset-php-7": true},
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "@babel/types",
					ID:         "id-@babel/types-5",
					ParentIDs:  map[string]bool{"id-@babel/parser-4": true},
					Version:    "7.26.5",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "@prettier/sync",
					ID:        "id-@prettier/sync-6",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 32),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "527e8ce",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "babel-preset-php",
					ID:        "id-babel-preset-php-7",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 34),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "1ae6dc1267500360b411ec711b8aeac8c68b2246",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					ID:        "id-is-number-8",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 36),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "98e8ff1",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					ID:        "id-is-number-9",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 38),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac058",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "is-number",
					ID:        "id-is-number-10",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 40),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "b7aef34",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "jquery",
					ID:         "id-jquery-11",
					ParentIDs:  map[string]bool{"id-slick-carousel-17": true},
					Version:    "3.7.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 42),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					ID:         "id-lodash-12",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.3.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 44),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "make-synchronized",
					ID:         "id-make-synchronized-13",
					ParentIDs:  map[string]bool{"id-@prettier/sync-6": true},
					Version:    "0.2.9",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 46),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "php-parser",
					ID:         "id-php-parser-14",
					ParentIDs:  map[string]bool{"id-babel-preset-php-7": true},
					Version:    "2.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 48),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "prettier",
					ID:         "id-prettier-15",
					ParentIDs:  map[string]bool{"id-@prettier/sync-6": true},
					Version:    "3.4.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 50),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "raven-js",
					ID:        "id-raven-js-16",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 52),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "91ef2d4",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "slick-carousel",
					ID:        "id-slick-carousel-17",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/commits.json5", 54),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "fc6f7d8",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "stopwords",
					ID:         "id-stopwords-18",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "0.0.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/commits.json5", 56),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:       "etag",
					ID:         "id-etag-1",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/files.json5", 15),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "lodash",
					ID:         "id-lodash-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.3.1",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/files.json5", 17),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "workspaces",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/workspaces.json5",
			},
			WantPackages: []*extractor.Package{
				{
					Name:       "has-flag",
					ID:         "id-has-flag-1",
					ParentIDs:  map[string]bool{"root": true, "id-supports-color-4": true},
					Version:    "4.0.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/workspaces.json5", 26),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "ms",
					ID:         "id-ms-2",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "2.1.3",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/workspaces.json5", 28),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "pkg-a",
					ID:         "id-pkg-a-3",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/workspaces.json5", 30),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "supports-color",
					ID:         "id-supports-color-4",
					ParentIDs:  map[string]bool{"id-pkg-a-3": true},
					Version:    "7.2.0",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/workspaces.json5", 32),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
				{
					Name:       "wrappy",
					ID:         "id-wrappy-5",
					ParentIDs:  map[string]bool{"root": true},
					Version:    "1.0.2",
					PURLType:   purl.TypeNPM,
					Location:   loc("testdata/workspaces.json5", 34),
					SourceCode: &extractor.SourceCodeIdentifier{},
					Metadata: &osv.DepGroupMetadata{
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
			WantPackages: []*extractor.Package{
				{
					Name:      "uWebSockets.js",
					ID:        "id-uWebSockets.js-1",
					ParentIDs: map[string]bool{"root": true},
					Version:   "",
					PURLType:  purl.TypeNPM,
					Location:  loc("testdata/blog-sample.json5", 11),
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "6609a88",
					},
					Metadata: &osv.DepGroupMetadata{
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extractor.SetIDGenerator(&testIDGenerator{})
			t.Cleanup(func() { extractor.SetIDGenerator(&extractor.RandomIDGenerator{}) })

			extr, err := bunlock.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("bunlock.New: %v", err)
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
