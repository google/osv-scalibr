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

package pomxml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{
			inputPath: "",
			want:      false,
		},
		{
			inputPath: "pom.xml",
			want:      true,
		},
		{
			inputPath: "path/to/my/pom.xml",
			want:      true,
		},
		{
			inputPath: "path/to/my/pom.xml/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/pom.xml.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.pom.xml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := pomxml.Extractor{}
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
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-pom.txt",
			},
			WantInventory: nil,
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "invalid syntax",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-syntax.xml",
			},
			WantInventory: nil,
			WantErr:       extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.apache.maven:maven-artifact",
					Version:   "1.0.0",
					Locations: []string{"testdata/one-package.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "maven-artifact",
						GroupID:      "org.apache.maven",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.42.Final",
					Locations: []string{"testdata/two-packages.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "netty-all",
						GroupID:      "io.netty",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/two-packages.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "slf4j-log4j12",
						GroupID:      "org.slf4j",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "with dependency management",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-dependency-management.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "io.netty:netty-all",
					Version:   "4.1.9",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "netty-all",
						GroupID:      "io.netty",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.slf4j:slf4j-log4j12",
					Version:   "1.7.25",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "slf4j-log4j12",
						GroupID:      "org.slf4j",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "com.google.code.findbugs:jsr305",
					Version:   "3.0.2",
					Locations: []string{"testdata/with-dependency-management.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "jsr305",
						GroupID:      "com.google.code.findbugs",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "interpolation",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/interpolation.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.mine:mypackage",
					Version:   "1.0.0",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "mypackage",
						GroupID:      "org.mine",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:my.package",
					Version:   "2.3.4",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "my.package",
						GroupID:      "org.mine",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.mine:ranged-package",
					Version:   "9.4.35.v20201120",
					Locations: []string{"testdata/interpolation.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "ranged-package",
						GroupID:      "org.mine",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "with scope",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-scope.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "abc:xyz",
					Version:   "1.2.3",
					Locations: []string{"testdata/with-scope.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "xyz",
						GroupID:      "abc",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "junit:junit",
					Version:   "4.12",
					Locations: []string{"testdata/with-scope.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "junit",
						GroupID:      "junit",
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
		{
			Name: "with type and classifier",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-type-classifier.xml",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "abc:xyz",
					Version:   "1.0.0",
					Locations: []string{"testdata/with-type-classifier.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "xyz",
						GroupID:      "abc",
						Type:         "pom",
						Classifier:   "sources",
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := pomxml.Extractor{}

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
