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

package ivyxml_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/ivyxml"
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
			inputPath: "ivy.xml",
			want:      true,
		},
		{
			inputPath: "path/to/my/ivy.xml",
			want:      true,
		},
		{
			inputPath: "path/to/my/ivy.xml/file",
			want:      false,
		},
		{
			inputPath: "path/to/my/ivy.xml.file",
			want:      false,
		},
		{
			inputPath: "path.to.my.ivy.xml",
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e, err := ivyxml.New(&cpb.PluginConfig{})
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
				Path: "testdata/not-ivy.txt",
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
			Name: "empty",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/empty.xml",
			},
			WantPackages: nil,
		},
		{
			Name: "no dependencies",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-dependencies.xml",
			},
			WantPackages: nil,
		},
		{
			Name: "valid",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.apache.commons:commons-lang3",
					Version:  "3.12.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/valid.xml", 3),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "commons-lang3",
						GroupID:      "org.apache.commons",
						DepGroupVals: []string{},
					},
				},
				{
					Name:     "org.junit:junit",
					Version:  "4.13.2",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/valid.xml", 4),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "junit",
						GroupID:      "org.junit",
						DepGroupVals: []string{"test"},
					},
				},
				{
					Name:     "com.google.guava:guava",
					Version:  "31.1-jre",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/valid.xml", 5),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "guava",
						GroupID:      "com.google.guava",
						DepGroupVals: []string{},
					},
				},
			},
		},
		{
			Name: "multiple configurations",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple-confs.xml",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.example:lib",
					Version:  "1.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-confs.xml", 3),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "lib",
						GroupID:      "org.example",
						DepGroupVals: []string{"compile", "runtime"},
					},
				},
				{
					Name:     "org.example:testlib",
					Version:  "2.0.0",
					PURLType: purl.TypeMaven,
					Location: extractor.LocationFromPathAndLine("testdata/multiple-confs.xml", 4),
					Metadata: &javalockfile.Metadata{
						ArtifactID:   "testlib",
						GroupID:      "org.example",
						DepGroupVals: []string{"test"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := ivyxml.New(&cpb.PluginConfig{})
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
