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

package gradlelockfile_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
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
			inputPath: "buildscript-gradle.lockfile",
			want:      true,
		},
		{
			inputPath: "path/to/my/buildscript-gradle.lockfile",
			want:      true,
		},
		{
			inputPath: "path/to/my/buildscript-gradle.lockfile/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/buildscript-gradle.lockfile.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.buildscript-gradle.lockfile",
			want:      false,
		},
		{
			inputPath: "gradle.lockfile",
			want:      true,
		},
		{
			inputPath: "path/to/my/gradle.lockfile",
			want:      true,
		},
		{
			inputPath: "path/to/my/gradle.lockfile/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/gradle.lockfile.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.gradle.lockfile",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := gradlelockfile.Extractor{}
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
			Name: "only comments",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-comments",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "empty statement",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/only-empty",
			},
			WantInventory: []*extractor.Inventory{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.security:spring-security-crypto",
					Version:   "5.7.3",
					Locations: []string{"testdata/one-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-security-crypto",
						GroupID:    "org.springframework.security",
					},
				},
			},
		},
		{
			Name: "multiple package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/5-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"testdata/5-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-autoconfigure",
						GroupID:    "org.springframework.boot",
					},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"testdata/5-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-configuration-processor",
						GroupID:    "org.springframework.boot",
					},
				},
				{
					Name:      "org.springframework.boot:spring-boot-devtools",
					Version:   "2.7.6",
					Locations: []string{"testdata/5-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-devtools",
						GroupID:    "org.springframework.boot",
					},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-aop",
					Version:   "2.7.7",
					Locations: []string{"testdata/5-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-starter-aop",
						GroupID:    "org.springframework.boot",
					},
				},
				{
					Name:      "org.springframework.boot:spring-boot-starter-data-jpa",
					Version:   "2.7.8",
					Locations: []string{"testdata/5-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-starter-data-jpa",
						GroupID:    "org.springframework.boot",
					},
				},
			},
		},
		{
			Name: "with invalid lines",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-bad-pkg",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:      "org.springframework.boot:spring-boot-autoconfigure",
					Version:   "2.7.4",
					Locations: []string{"testdata/with-bad-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-autoconfigure",
						GroupID:    "org.springframework.boot",
					},
				},
				{
					Name:      "org.springframework.boot:spring-boot-configuration-processor",
					Version:   "2.7.5",
					Locations: []string{"testdata/with-bad-pkg"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "spring-boot-configuration-processor",
						GroupID:    "org.springframework.boot",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gradlelockfile.Extractor{}

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
