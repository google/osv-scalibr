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

package asdf_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/asdf"
	asdfmeta "github.com/google/osv-scalibr/extractor/filesystem/os/asdf/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = asdf.Extractor{}
			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: 30 * 1024,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func pkgLess(i1, i2 *extractor.Package) bool {
	return i1.Name < i2.Name
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		content      string
		wantPackages []*extractor.Package
	}{
		{
			name:    "valid .tool-versions ",
			path:    "/home/user/.tool-versions",
			content: `nodejs 24.04`,
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"/home/user/.tool-versions"},
				},
			},
		}, {
			name:    "valid .tool-versions multiple versions",
			path:    "/home/user/.tool-versions",
			content: `nodejs 24.04 21 19.0`,
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"/home/user/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Locations: []string{"/home/user/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Locations: []string{"/home/user/.tool-versions"},
				},
			},
		}, {
			name:    "valid .tool-versions multiple versions with skip values",
			path:    "/home/user/.tool-versions",
			content: `nodejs 24.04 21 system file:/dev/null 19.0`,
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"/home/user/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "21",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "21",
					},
					Locations: []string{"/home/user/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "19.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "19.0",
					},
					Locations: []string{"/home/user/.tool-versions"},
				},
			},
		}, {
			name:    "valid .tool-versions multiple lines",
			path:    "/home/user/.tool-versions",
			content: "nodejs 24.04\nnodejs 20.0",
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"/home/user/.tool-versions"},
				}, {
					Name:     "nodejs",
					Version:  "20.0",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "20.0",
					},
					Locations: []string{"/home/user/.tool-versions"},
				},
			},
		}, {
			name:    "valid .tool-versions more whitespaces",
			path:    "/home/user/.tool-versions",
			content: `nodejs   24.04  `,
			wantPackages: []*extractor.Package{
				{
					Name:     "nodejs",
					Version:  "24.04",
					PURLType: purl.TypeAsdf,
					Metadata: &asdfmeta.Metadata{
						ToolName:    "nodejs",
						ToolVersion: "24.04",
					},
					Locations: []string{"/home/user/.tool-versions"},
				},
			},
		},
		{
			name:         "invalid .tool-versions ",
			path:         "/home/user/.tool-versions",
			content:      `nodejs24.04`,
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = asdf.Extractor{}
			input := &filesystem.ScanInput{Path: tt.path, Reader: strings.NewReader(tt.content)}
			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Errorf("Extract(%s) unexpected error :\n%s", input, err.Error())
			}

			want := inventory.Inventory{Packages: tt.wantPackages}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(pkgLess)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
