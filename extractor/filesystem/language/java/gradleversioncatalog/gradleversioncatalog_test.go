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

package gradleversioncatalog_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleversioncatalog"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
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
		{name: "empty path", inputPath: "", want: false},
		{name: "default catalog filename", inputPath: "libs.versions.toml", want: true},
		{name: "default catalog in subdir", inputPath: "path/to/libs.versions.toml", want: true},
		{name: "default catalog in gradle dir", inputPath: "gradle/libs.versions.toml", want: true},
		{name: "additional catalog under gradle dir", inputPath: "gradle/testLibs.versions.toml", want: true},
		{name: "additional catalog under deep gradle dir", inputPath: "a/b/gradle/testLibs.versions.toml", want: true},
		{name: "additional catalog outside gradle dir is skipped", inputPath: "src/testLibs.versions.toml", want: false},
		{name: "suffix-only is not a match", inputPath: "path/to/libs.versions.toml.bak", want: false},
		{name: "dotted-name not in gradle dir is skipped", inputPath: "path.to.my.libs.versions.toml", want: false},
		{name: "unrelated toml file is skipped", inputPath: "Cargo.toml", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gradleversioncatalog.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "invalid toml returns error",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.versions.toml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "failed to parse"},
		},
		{
			Name: "not-toml returns error",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-toml.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "failed to parse"},
		},
		{
			Name: "empty libraries section yields no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.versions.toml",
			},
			WantPackages: nil,
		},
		{
			Name: "all library shapes",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/libs.versions.toml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.google.guava:guava",
					Version:  "30.1.1-jre",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "com.google.guava", ArtifactID: "guava"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "com.puppycrawl.tools:checkstyle",
					Version:  "8.37",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "com.puppycrawl.tools", ArtifactID: "checkstyle"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.codehaus.groovy:groovy",
					Version:  "3.0.5",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.codehaus.groovy", ArtifactID: "groovy"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.apache.commons:commons-lang3",
					Version:  "3.12.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.apache.commons", ArtifactID: "commons-lang3"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.example:strict",
					Version:  "2.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.example", ArtifactID: "strict"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.example:req",
					Version:  "1.5",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.example", ArtifactID: "req"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.example:pref",
					Version:  "1.0",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.example", ArtifactID: "pref"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.codehaus.groovy:groovy-json",
					Version:  "3.0.5",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.codehaus.groovy", ArtifactID: "groovy-json"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
				{
					Name:     "org.example:noversion",
					Version:  "",
					PURLType: purl.TypeMaven,
					Metadata: &javalockfile.Metadata{GroupID: "org.example", ArtifactID: "noversion"},
					Location: extractor.LocationFromPath("testdata/libs.versions.toml"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gradleversioncatalog.Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatalf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
