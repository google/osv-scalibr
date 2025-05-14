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

package gradleverificationmetadataxml_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
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
		{
			name:      "Empty string",
			inputPath: "",
			want:      false,
		},
		{
			name:      "file name by itself",
			inputPath: "verification-metadata.xml",
			want:      false,
		},
		{
			name:      "file under gradle directory",
			inputPath: "gradle/verification-metadata.xml",
			want:      true,
		},
		{
			name:      "file not under gradle directory",
			inputPath: "path/to/my/verification-metadata.xml",
			want:      false,
		},
		{
			name:      "more path after file name, not in gradle directory",
			inputPath: "path/to/my/verification-metadata.xml/file",
			want:      false,
		},
		{
			name:      "wrong extension, not in gradle directory",
			inputPath: "path/to/my/verification-metadata.xml.file",
			want:      false,
		},
		{
			name:      "file name as suffix, not in gradle directory",
			inputPath: "path.to.my.verification-metadata.xml",
			want:      false,
		},
		{
			name:      "nested file in gradle directory",
			inputPath: "path/to/my/gradle/verification-metadata.xml",
			want:      true,
		},
		{
			name:      "more path after file name, in gradle directory",
			inputPath: "path/to/my/gradle/verification-metadata.xml/file",
			want:      false,
		},
		{
			name:      "wrong extension, in gradle directory",
			inputPath: "path/to/my/gradle/verification-metadata.xml.file",
			want:      false,
		},
		{
			name:      "gradle in file name instead of as parent directory",
			inputPath: "path.to.my.gradle.verification-metadata.xml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := gradleverificationmetadataxml.Extractor{}
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
			Name: "invalid xml",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-xml.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract from"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantPackages: []*extractor.Package{},
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "org.apache.pdfbox:pdfbox",
					Version:   "2.0.17",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/one-package.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "pdfbox", GroupID: "org.apache.pdfbox"},
				},
			},
		},
		{
			Name: "two packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/two-packages.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "org.apache.pdfbox:pdfbox",
					Version:   "2.0.17",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/two-packages.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "pdfbox", GroupID: "org.apache.pdfbox"},
				},
				{
					Name:      "com.github.javaparser:javaparser-core",
					Version:   "3.6.11",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/two-packages.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "javaparser-core", GroupID: "com.github.javaparser"},
				},
			},
		},
		{
			Name: "multiple versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-versions.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "androidx.activity:activity",
					Version:   "1.2.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.2.3",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.5.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.6.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.7.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity",
					Version:   "1.7.2",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.5.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-compose", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.7.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-compose", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-compose",
					Version:   "1.7.2",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-compose", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.5.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-ktx", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.7.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-ktx", GroupID: "androidx.activity"},
				},
				{
					Name:      "androidx.activity:activity-ktx",
					Version:   "1.7.2",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "activity-ktx", GroupID: "androidx.activity"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "ktor-serialization-jvm", GroupID: "io.ktor"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.0-beta-1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "ktor-serialization-jvm", GroupID: "io.ktor"},
				},
				{
					Name:      "io.ktor:ktor-serialization-jvm",
					Version:   "2.0.3",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "ktor-serialization-jvm", GroupID: "io.ktor"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.0-rc4",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "auto-service", GroupID: "com.google.auto.service"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.0.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "auto-service", GroupID: "com.google.auto.service"},
				},
				{
					Name:      "com.google.auto.service:auto-service",
					Version:   "1.1.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/multiple-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "auto-service", GroupID: "com.google.auto.service"},
				},
			},
		},
		{
			Name: "odd versions",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/odd-versions.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:      "com.google:google",
					Version:   "1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "google", GroupID: "com.google"},
				},
				{
					Name:      "com.almworks.sqlite4java:sqlite4java",
					Version:   "0.282",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "sqlite4java", GroupID: "com.almworks.sqlite4java"},
				},
				{
					Name:      "com.google.errorprone:javac",
					Version:   "9+181-r4173-1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "javac", GroupID: "com.google.errorprone"},
				},
				{
					Name:      "com.android.tools.build:aapt2",
					Version:   "8.3.0-10880808",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "aapt2", GroupID: "com.android.tools.build"},
				},
				{
					Name:      "com.android.tools.build:aapt2-proto",
					Version:   "8.3.0-10880808",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "aapt2-proto", GroupID: "com.android.tools.build"},
				},
				{
					Name:      "com.android.tools.build:transform-api",
					Version:   "2.0.0-deprecated-use-gradle-api",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "transform-api", GroupID: "com.android.tools.build"},
				},
				{
					Name:      "com.android.tools.build.jetifier:jetifier-core",
					Version:   "1.0.0-beta10",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "jetifier-core", GroupID: "com.android.tools.build.jetifier"},
				},
				{
					Name:      "com.google.apis:google-api-services-androidpublisher",
					Version:   "v3-rev20231115-2.0.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "google-api-services-androidpublisher", GroupID: "com.google.apis"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing",
					Version:   "1.9.22-1.0.17",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "symbol-processing", GroupID: "com.google.devtools.ksp"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing-api",
					Version:   "1.9.22-1.0.17",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "symbol-processing-api", GroupID: "com.google.devtools.ksp"},
				},
				{
					Name:      "com.google.devtools.ksp:symbol-processing-gradle-plugin",
					Version:   "1.9.22-1.0.17",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata: &javalockfile.Metadata{
						ArtifactID: "symbol-processing-gradle-plugin",
						GroupID:    "com.google.devtools.ksp",
					},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "32.0.0-jre",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "guava", GroupID: "com.google.guava"},
				},
				{
					Name:      "com.google.guava:guava",
					Version:   "32.1.3-jre",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "guava", GroupID: "com.google.guava"},
				},
				{
					Name:      "com.google.guava:listenablefuture",
					Version:   "9999.0-empty-to-avoid-conflict-with-guava",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "listenablefuture", GroupID: "com.google.guava"},
				},
				{
					Name:      "com.google.testing.platform:core",
					Version:   "0.0.9-alpha02",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "core", GroupID: "com.google.testing.platform"},
				},
				{
					Name:      "com.jakewharton.android.repackaged:dalvik-dx",
					Version:   "9.0.0_r3",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "dalvik-dx", GroupID: "com.jakewharton.android.repackaged"},
				},
				{
					Name:      "com.vaadin.external.google:android-json",
					Version:   "0.0.20131108.vaadin1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "android-json", GroupID: "com.vaadin.external.google"},
				},
				{
					Name:      "de.mannodermaus.gradle.plugins:android-junit5",
					Version:   "1.10.0.0",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "android-junit5", GroupID: "de.mannodermaus.gradle.plugins"},
				},
				{
					Name:      "io.netty:netty-codec-http",
					Version:   "4.1.93.Final",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "netty-codec-http", GroupID: "io.netty"},
				},
				{
					Name:      "io.netty:netty-codec-http2",
					Version:   "4.1.93.Final",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "netty-codec-http2", GroupID: "io.netty"},
				},
				{
					Name:      "javax.inject:javax.inject",
					Version:   "1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "javax.inject", GroupID: "javax.inject"},
				},
				{
					Name:      "junit:junit",
					Version:   "4.13.2",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "junit", GroupID: "junit"},
				},
				{
					Name:      "org.apache:apache",
					Version:   "13",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "apache", GroupID: "org.apache"},
				},
				{
					Name:      "org.jetbrains.intellij.deps:trove4j",
					Version:   "1.0.20200330",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "trove4j", GroupID: "org.jetbrains.intellij.deps"},
				},
				{
					Name:      "org.json:json",
					Version:   "20180813",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "json", GroupID: "org.json"},
				},
				{
					Name:      "org.tensorflow:tensorflow-lite-metadata",
					Version:   "0.1.0-rc2",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "tensorflow-lite-metadata", GroupID: "org.tensorflow"},
				},
				{
					Name:      "org.tukaani:xz",
					Version:   "1.9",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "xz", GroupID: "org.tukaani"},
				},
				{
					Name:      "org.whitesource:pecoff4j",
					Version:   "0.0.2.1",
					PURLType:  purl.TypeMaven,
					Locations: []string{"testdata/odd-versions.xml"},
					Metadata:  &javalockfile.Metadata{ArtifactID: "pecoff4j", GroupID: "org.whitesource"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := gradleverificationmetadataxml.Extractor{}

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
