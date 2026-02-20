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

package sbt_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/scala/sbt"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			inputPath: "build.sbt",
			want:      true,
		},
		{
			inputPath: "project/Dependencies.sbt",
			want:      true,
		},
		{
			inputPath: "path/to/my/build.sbt",
			want:      true,
		},
		{
			inputPath: "pom.xml",
			want:      false,
		},
		{
			inputPath: "build.sbt.bak",
			want:      false,
		},
		{
			inputPath: "path/to/my/build.sbt/file",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := sbt.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("sbt.New: %v", err)
			}
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
			Name: "empty_sbt_file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.sbt",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid_sbt_file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.sbt",
			},
			WantPackages: nil,
		},
		{
			Name: "valid_sbt_with_inline_versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.sbt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "org.scala-native:scala-native-java-logging",
					Version:   "1.0.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "scala-native-java-logging",
						GroupID:      "org.scala-native",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "com.twitter:finagle-core",
					Version:   "24.2.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "finagle-core",
						GroupID:      "com.twitter",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.scala-lang:toolkit_3",
					Version:   "0.2.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "toolkit_3",
						GroupID:      "org.scala-lang",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.apache.pekko:pekko-testkit",
					Version:   "1.4.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "pekko-testkit",
						GroupID:      "org.apache.pekko",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "valid_sbt_with_separate_version_variables",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid_separate_version.sbt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "dev.zio:zio",
					Version:   "2.1.24",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid_separate_version.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "zio",
						GroupID:      "dev.zio",
						DepGroupVals: []string{},
					},
				},
				{
					Name:      "org.typelevel:cats-effect",
					Version:   "3.6.3",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/valid_separate_version.sbt"},
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "cats-effect",
						GroupID:      "org.typelevel",
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := sbt.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("sbt.New: %v", err)
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
