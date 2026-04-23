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
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/scala/sbt"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "build.sbt file",
			path:             "build.sbt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "nested build.sbt file",
			path:             "project/Dependencies.sbt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "deeply nested sbt file",
			path:             "path/to/my/build.sbt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "non-sbt file",
			path:         "pom.xml",
			wantRequired: false,
		},
		{
			name:         "sbt backup file",
			path:         "build.sbt.bak",
			wantRequired: false,
		},
		{
			name:             "sbt file required if file size < max file size",
			path:             "build.sbt",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "sbt file required if file size == max file size",
			path:             "build.sbt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "sbt file not required if file size > max file size",
			path:             "build.sbt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "sbt file required if max file size set to 0",
			path:             "build.sbt",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := sbt.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("sbt.New: %v", err)
			}
			e.(*sbt.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "empty sbt file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.sbt",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid sbt file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid.sbt",
			},
			WantPackages: nil,
		},
		{
			Name: "valid sbt with inline versions and Seq block",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.sbt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.scala-native:scala-native-java-logging",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "scala-native-java-logging",
						GroupID:      "org.scala-native",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "com.twitter:finagle-core",
					Version:  "24.2.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "finagle-core",
						GroupID:      "com.twitter",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.scala-lang:toolkit_3",
					Version:  "0.2.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "toolkit_3",
						GroupID:      "org.scala-lang",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.apache.pekko:pekko-testkit",
					Version:  "1.4.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "pekko-testkit",
						GroupID:      "org.apache.pekko",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.dep1:toolkit",
					Version:  "1.2.3",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "toolkit",
						GroupID:      "org.dep1",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.dep2:toolkit",
					Version:  "4.5.6",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "toolkit",
						GroupID:      "org.dep2",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "valid sbt with variable version references",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid_variable.sbt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "dev.zio:zio",
					Version:  "2.1.24",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid_variable.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "zio",
						GroupID:      "dev.zio",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.typelevel:cats-effect",
					Version:  "3.6.3",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/valid_variable.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "cats-effect",
						GroupID:      "org.typelevel",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "Seq block with variable versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/seq_with_vars.sbt",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.typesafe.akka:akka-actor",
					Version:  "2.9.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/seq_with_vars.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "akka-actor",
						GroupID:      "com.typesafe.akka",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "com.typesafe.akka:akka-stream",
					Version:  "2.9.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/seq_with_vars.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "akka-stream",
						GroupID:      "com.typesafe.akka",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.scalatest:scalatest",
					Version:  "3.2.18",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPath("testdata/seq_with_vars.sbt"),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "scalatest",
						GroupID:      "org.scalatest",
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := sbt.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("sbt.New: %v", err)
			}
			e.(*sbt.Extractor).Stats = collector

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
