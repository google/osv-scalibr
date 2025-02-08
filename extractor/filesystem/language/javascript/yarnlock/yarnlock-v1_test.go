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

package yarnlock_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_Extract_v1(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.v1.lock",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "balanced-match",
					Version:   "1.0.2",
					Locations: []string{"testdata/one-package.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "package with no version in header",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-version.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "balanced-match",
					Version:   "1.0.2",
					Locations: []string{"testdata/no-version.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "concat-stream",
					Version:   "1.6.2",
					Locations: []string{"testdata/two-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"testdata/two-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with quotes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-quotes.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "concat-stream",
					Version:   "1.6.2",
					Locations: []string{"testdata/with-quotes.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "concat-map",
					Version:   "0.0.1",
					Locations: []string{"testdata/with-quotes.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "define-properties",
					Version:   "1.1.3",
					Locations: []string{"testdata/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "0.2.5",
					Locations: []string{"testdata/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "1.0.0",
					Locations: []string{"testdata/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "define-property",
					Version:   "2.0.2",
					Locations: []string{"testdata/multiple-versions.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "multiple constraints",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-constraints.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.12.13",
					Locations: []string{"testdata/multiple-constraints.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "domelementtype",
					Version:   "1.3.1",
					Locations: []string{"testdata/multiple-constraints.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "scoped packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/scoped-packages.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/code-frame",
					Version:   "7.12.11",
					Locations: []string{"testdata/scoped-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "@babel/compat-data",
					Version:   "7.14.0",
					Locations: []string{"testdata/scoped-packages.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with prerelease",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-prerelease.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "css-tree",
					Version:   "1.0.0-alpha.37",
					Locations: []string{"testdata/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "gensync",
					Version:   "1.0.0-beta.2",
					Locations: []string{"testdata/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "node-fetch",
					Version:   "3.0.0-beta.9",
					Locations: []string{"testdata/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "resolve",
					Version:   "1.20.0",
					Locations: []string{"testdata/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "resolve",
					Version:   "2.0.0-next.3",
					Locations: []string{"testdata/with-prerelease.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with build string",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-build-string.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "domino",
					Version:   "2.1.6+git",
					Locations: []string{"testdata/with-build-string.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "tslib",
					Version:   "2.6.2",
					Locations: []string{"testdata/with-build-string.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "commits",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/commits.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "mine1",
					Version:   "1.0.0-alpha.37",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
					},
				},
				{
					Name:      "mine2",
					Version:   "0.0.1",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "0a2d2506c1fe299691fc5db53a2097db3bd615bc",
					},
				},
				{
					Name:      "mine3",
					Version:   "1.2.3",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "094e581aaf927d010e4b61d706ba584551dac502",
					},
				},
				{
					Name:      "mine4",
					Version:   "0.0.2",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
					},
				},
				{
					Name:      "mine4",
					Version:   "0.0.4",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "aa3bdfcb1d845c79f14abb66f60d35b8a3ee5998",
					},
				},
				{
					Name:      "my-package",
					Version:   "1.8.3",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "b3bd3f1b3dad036e671251f5258beaae398f983a",
					},
				},
				{
					Name:      "@bower_components/angular-animate",
					Version:   "1.4.14",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e7f778fc054a086ba3326d898a00fa1bc78650a8",
					},
				},
				{
					Name:      "@bower_components/alertify",
					Version:   "0.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "e7b6c46d76604d297c389d830817b611c9a8f17c",
					},
				},
				{
					Name:      "minimist",
					Version:   "0.0.8",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "3754568bfd43a841d2d72d7fb54598635aea8fa4",
					},
				},
				{
					Name:      "bats-assert",
					Version:   "2.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "4bdd58d3fbcdce3209033d44d884e87add1d8405",
					},
				},
				{
					Name:      "bats-support",
					Version:   "0.3.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d140a65044b2d6810381935ae7f0c94c7023c8c3",
					},
				},
				{
					Name:      "bats",
					Version:   "1.5.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "172580d2ce19ee33780b5f1df817bbddced43789",
					},
				},
				{
					Name:      "vue",
					Version:   "2.6.12",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "bb253db0b3e17124b6d1fe93fbf2db35470a1347",
					},
				},
				{
					Name:      "kit",
					Version:   "1.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "5b6830c0252eb73c6024d40a8ff5106d3023a2a6",
					},
				},
				{
					Name:      "casadistance",
					Version:   "1.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "f0308391f0c50104182bfb2332a53e4e523a4603",
					},
				},
				{
					Name:      "babel-preset-php",
					Version:   "1.1.1",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "c5a7ba5e0ad98b8db1cb8ce105403dd4b768cced",
					},
				},
				{
					Name:      "is-number",
					Version:   "2.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "d5ac0584ee9ae7bd9288220a39780f155b9ad4c8",
					},
				},
				{
					Name:      "is-number",
					Version:   "5.0.0",
					Locations: []string{"testdata/commits.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "af885e2e890b9ef0875edd2b117305119ee5bdc5",
					},
				},
			},
		},
		{
			Name: "files",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/files.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "etag",
					Version:   "1.8.1",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "filedep",
					Version:   "1.2.0",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "lodash",
					Version:   "1.3.1",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "other_package",
					Version:   "0.0.2",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "sprintf-js",
					Version:   "0.0.0",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "etag",
					Version:   "1.8.0",
					Locations: []string{"testdata/files.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
		{
			Name: "with aliases",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-aliases.v1.lock",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "@babel/helper-validator-identifier",
					Version:   "7.22.20",
					Locations: []string{"testdata/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "6.0.1",
					Locations: []string{"testdata/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
				{
					Name:      "ansi-regex",
					Version:   "5.0.1",
					Locations: []string{"testdata/with-aliases.v1.lock"},
					SourceCode: &extractor.SourceCodeIdentifier{
						Commit: "",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := yarnlock.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)

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
