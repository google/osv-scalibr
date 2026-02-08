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

package bazelmaven

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	bazelmavenmeta "github.com/google/osv-scalibr/extractor/filesystem/misc/bazelmaven/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "basic maven_install",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/MODULE.bazel",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "group1:artifact1",
					Version:  "1",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group1:artifact1",
						GroupID:    "group1",
						ArtifactID: "artifact1",
						Version:    "1",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group2:artifact2",
					Version:  "2",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group2:artifact2",
						GroupID:    "group2",
						ArtifactID: "artifact2",
						Version:    "2",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group3:artifact3",
					Version:  "3",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group3:artifact3",
						GroupID:    "group3",
						ArtifactID: "artifact3",
						Version:    "3",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group4:artifact4",
					Version:  "4",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group4:artifact4",
						GroupID:    "group4",
						ArtifactID: "artifact4",
						Version:    "4",
						RuleName:   "maven.install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group5:artifact5",
					Version:  "5",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group5:artifact5",
						GroupID:    "group5",
						ArtifactID: "artifact5",
						Version:    "5",
						RuleName:   "maven.artifact",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group6:artifact6",
					Version:  "6",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group6:artifact6",
						GroupID:    "group6",
						ArtifactID: "artifact6",
						Version:    "6",
						RuleName:   "maven_install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
				{
					Name:     "group7:artifact7",
					Version:  "7",
					PURLType: purl.TypeMaven,
					Metadata: &bazelmavenmeta.Metadata{
						Name:       "group7:artifact7",
						GroupID:    "group7",
						ArtifactID: "artifact7",
						Version:    "7",
						RuleName:   "maven_install",
					},
					Locations: []string{"testdata/MODULE.bazel"},
				},
			},
		},
		{
			Name: "empty build file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/EMPTY.bazel",
			},
			WantPackages: nil,
		},
		{
			Name: "invalid build file",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/INVALID.bazel",
			},
			WantErr: extracttest.ContainsErrStr{Str: "failed to parse Bazel file"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := Extractor{}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			want := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "BUILD.bazel file valid",
			path:         "/usr/local/go/src/BUILD.bazel",
			wantRequired: true,
		},
		{
			name:         "MODULE.bazel file valid",
			path:         "/usr/local/go/src/MODULE.bazel",
			wantRequired: true,
		},
		{
			name:         "WORKSPACE file valid",
			path:         "/usr/local/go/src/WORKSPACE",
			wantRequired: true,
		},
		{
			name:         "BUILD.bazel in nested directory",
			path:         "/usr/local/go/src/project/subdir/BUILD.bazel",
			wantRequired: true,
		},
		{
			name:         "MODULE.bazel in nested directory",
			path:         "/usr/local/go/pkg/MODULE.bazel",
			wantRequired: true,
		},
		{
			name:         "WORKSPACE in nested directory",
			path:         "/usr/local/go/bin/project/WORKSPACE",
			wantRequired: true,
		},
		{
			name:         "invalid file - BUILD without .bazel extension",
			path:         "/usr/local/go/src/BUILD",
			wantRequired: false,
		},
		{
			name:         "invalid file - random .bazel file",
			path:         "/usr/local/go/src/random.bazel",
			wantRequired: false,
		},
		{
			name:         "invalid file - not bazel related",
			path:         "/usr/local/go/src/main.go",
			wantRequired: false,
		},
		{
			name:         "invalid file - similar name but wrong",
			path:         "/usr/local/go/src/MODULE.bazel.txt",
			wantRequired: false,
		},
		{
			name:         "invalid file - WORKSPACE with extension",
			path:         "/usr/local/go/src/WORKSPACE.txt",
			wantRequired: false,
		},
		{
			name:         "invalid path - empty",
			path:         "",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = Extractor{}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: 1024,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}
