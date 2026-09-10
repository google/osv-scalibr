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

package pomxml

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
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
			inputPath: "pom.xml",
			want:      true,
		},
		{
			inputPath: "my-app-1.0.pom",
			want:      true,
		},
		{
			inputPath: "path/to/my/pom.xml",
			want:      true,
		},
		{
			inputPath: "path/to/my/pom/my-app-1.0.pom",
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
			e, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
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
			Name: "invalid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not-pom.txt",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "invalid syntax",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-syntax.xml",
			},
			WantPackages: nil,
			WantErr:      extracttest.ContainsErrStr{Str: "could not extract"},
		},
		{
			Name: "no packages",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantPackages: nil,
		},
		{
			Name: "one package",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/one-package.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.apache.maven:maven-artifact",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/one-package.xml", 7),
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
			WantPackages: []*extractor.Package{
				{
					Name:     "io.netty:netty-all",
					Version:  "4.1.42.Final",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.xml", 7),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "netty-all",
						GroupID:      "io.netty",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.slf4j:slf4j-log4j12",
					Version:  "1.7.25",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/two-packages.xml", 12),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "slf4j-log4j12",
						GroupID:      "org.slf4j",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "different_encoding",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/encoding.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "junit:junit",
					Version:  "4.12",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/encoding.xml", 16),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "junit",
						GroupID:      "junit",
						IsTransitive: false,
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
			WantPackages: []*extractor.Package{
				{
					Name:     "io.netty:netty-all",
					Version:  "4.1.9",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-dependency-management.xml", 7),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "netty-all",
						GroupID:      "io.netty",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.slf4j:slf4j-log4j12",
					Version:  "1.7.25",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-dependency-management.xml", 12),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "slf4j-log4j12",
						GroupID:      "org.slf4j",
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
			WantPackages: []*extractor.Package{
				{
					Name:     "org.mine:mypackage",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/interpolation.xml", 18),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "mypackage",
						GroupID:      "org.mine",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.mine:my.package",
					Version:  "2.3.4",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/interpolation.xml", 24),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "my.package",
						GroupID:      "org.mine",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.mine:ranged-package",
					Version:  "9.4.35.v20201120",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/interpolation.xml", 30),
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
			WantPackages: []*extractor.Package{
				{
					Name:     "abc:xyz",
					Version:  "1.2.3",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-scope.xml", 3),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "xyz",
						GroupID:      "abc",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "junit:junit",
					Version:  "4.12",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-scope.xml", 9),
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
			WantPackages: []*extractor.Package{
				{
					Name:     "abc:xyz",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-type-classifier.xml", 3),
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
		{
			Name: "with parent",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-parent.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.alice:alice",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-parent.xml", 18),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "alice",
						GroupID:      "org.alice",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.bob:bob",
					Version:  "2.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-parent.xml", 23),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "bob",
						GroupID:      "org.bob",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.chuck:chuck",
					Version:  "3.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-parent.xml", 28),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "chuck",
						GroupID:      "org.chuck",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.dave:dave",
					Version:  "4.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-parent.xml", 6),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "dave",
						GroupID:      "org.dave",
						DepGroupVals: []string{},
					},
				},
				{
					Name: "org.frank:frank",
					// Version is not available in the local pom.xml.
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-parent.xml", 32),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "frank",
						GroupID:      "org.frank",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "transitive dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/transitive.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.direct:alice",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/transitive.xml", 17),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "alice",
						GroupID:      "org.direct",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.direct:bob",
					Version:  "2.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/transitive.xml", 22),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "bob",
						GroupID:      "org.direct",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.direct:chris",
					Version:  "3.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/transitive.xml", 27),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "chris",
						GroupID:      "org.direct",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "interpolate and drop",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/interpolate-drop.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.example:actual-artifact",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/interpolate-drop.xml", 11),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "actual-artifact",
						GroupID:      "com.example",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "profiles",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/profiles.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.profile:profile-dep",
					Version:  "1.2.3",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/profiles.xml", 15),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "profile-dep",
						GroupID:      "org.profile",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "ambiguous interpolation",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/ambiguous-interpolation.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.example:common-lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/ambiguous-interpolation.xml", 0),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "common-lib",
						GroupID:      "com.example",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "plugin dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/plugin-dependency.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.example:hijack-lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/plugin-dependency.xml", 27),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "hijack-lib",
						GroupID:      "com.example",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "explicit jar type",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/explicit-jar.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.example:my-lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/explicit-jar.xml", 23),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "my-lib",
						GroupID:      "com.example",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.different:my-lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/explicit-jar.xml", 12),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "my-lib",
						GroupID:      "org.different",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "with multiple classifiers",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/with-multiple-classifiers.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "com.example:my-lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/with-multiple-classifiers.xml", 14),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "my-lib",
						GroupID:      "com.example",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multi version dependency",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multi-version.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "abc:example.com",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/multi-version.xml", 8),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "example.com",
						GroupID:      "abc",
						IsTransitive: false,
						DepGroupVals: []string{},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New: %v", err)
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
