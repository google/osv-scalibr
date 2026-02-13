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

package homebrew_test

import (
	"runtime"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	metadata "github.com/google/osv-scalibr/extractor/filesystem/os/homebrew/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	if slices.Contains([]string{"windows"}, runtime.GOOS) {
		t.Skipf("Skipping test for unsupported OS %q", runtime.GOOS)
	}
	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "cellar.valid.json",
			path:           "somefolder/Cellar/rclone/1.67.0/INSTALL_RECEIPT.json",
			wantIsRequired: true,
		},
		{
			name:           "cellar.invalid.json.filename",
			path:           "somefolder/Cellar/rclone/1.67.0/other.json",
			wantIsRequired: false,
		},
		{
			name:           "cellar.invalid.json.extension",
			path:           "somefolder/Cellar/rclone/1.67.0/INSTALL_RECEIPT.json2",
			wantIsRequired: false,
		},
		{
			name:           "Caskroom.nonstandard.version.folder.check",
			path:           "somefolder/Caskroom/somefolder/latest/somefolder-app/source.properties",
			wantIsRequired: true,
		},
		{
			name:           "caskroom.wrapper.sh.variation",
			path:           "somefolder/Caskroom/testapp/1.1.1/testapp.wrapper.sh",
			wantIsRequired: true,
		},
		{
			name:           "caskroom.source.properties.longer.path.variation",
			path:           "somefolder/Caskroom/android-platform-tools/35.0.2/platform-tools/source.properties",
			wantIsRequired: true,
		},
		{
			name:           "caskroom.app.variation",
			path:           "somefolder/Caskroom/firefox/130.0.1/firefox.app",
			wantIsRequired: true,
		},
		{
			name:           "caskroom.missing.folder.failure",
			path:           "somefolder/Caskroom/somefolder/2.3",
			wantIsRequired: false,
		},
		{
			name:           "caskroom.missing.file.failure",
			path:           "somefolder/Caskroom/somefolder/1.1/",
			wantIsRequired: false,
		},
		{
			name:           "Caskroom.invalid.json.filename",
			path:           "somefolder/Caskroom/rclone/1.67.0/INSTALL_RECEIPT.json",
			wantIsRequired: false,
		},
		{
			name:           "generally.wrong.path",
			path:           "somefolder/otherfile.json",
			wantIsRequired: false,
		},
		{
			name:           "caskroom.invalid.suffix",
			path:           "somefolder/Caskroom/testapp/1.1.1/testapp.app/Contents/PkgInfo",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := homebrew.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("homebrew.New: %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantIsRequired)
			}
		})
	}
}

func pkgLess(i1, i2 *extractor.Package) bool {
	return i1.Name < i2.Name
}

func TestExtract(t *testing.T) {
	if slices.Contains([]string{"windows"}, runtime.GOOS) {
		t.Skipf("Skipping test for unsupported OS %q", runtime.GOOS)
	}
	tests := []struct {
		name         string
		path         string
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			name: "cellar.valid.json",
			path: "testdata/Cellar/rclone/1.67.0/INSTALL_RECEIPT.json",
			wantPackages: []*extractor.Package{
				{
					Name:      "rclone",
					Version:   "1.67.0",
					PURLType:  purl.TypeBrew,
					Locations: []string{"testdata/Cellar/rclone/1.67.0/INSTALL_RECEIPT.json"},
					Metadata: &metadata.Metadata{
						URL:  "https://github.com/rclone/rclone/archive/refs/tags/v1.67.0.tar.gz",
						Head: "https://github.com/rclone/rclone.git",
						Mirrors: []string{
							"https://github.com/rclone/rclone/archive/refs/tags/v1.67.0.tar.gz",
							"https://github.com/rclone/rclone/archive/refs/tags/v1.67.0.tar.gz",
						},
					},
				},
			},
		},
		{
			name: "caskroom.valid.json",
			path: "testdata/Caskroom/testapp/1.1.1/testapp.wrapper.sh",
			wantPackages: []*extractor.Package{
				{
					Name:      "testapp",
					Version:   "1.1.1",
					PURLType:  purl.TypeBrew,
					Locations: []string{"testdata/Caskroom/testapp/1.1.1/testapp.wrapper.sh"},
				},
			},
		},
		{
			name:         "caskroom.null.variation",
			path:         "testdata/Caskroom/somefolder/2.2",
			wantPackages: nil,
		},
		{
			name: "caskroom.other.variation",
			path: "testdata/Caskroom/android-platform-tools/35.0.2/platform-tools/source.properties",
			wantPackages: []*extractor.Package{
				{
					Name:      "android-platform-tools",
					Version:   "35.0.2",
					PURLType:  purl.TypeBrew,
					Locations: []string{"testdata/Caskroom/android-platform-tools/35.0.2/platform-tools/source.properties"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := homebrew.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("homebrew.New: %v", err)
			}
			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Reader: nil}
			got, err := e.Extract(t.Context(), input)
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract(%s) unexpected error (-want +got):\n%s", tt.path, diff)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(pkgLess)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestSplitPath(t *testing.T) {
	if slices.Contains([]string{"windows"}, runtime.GOOS) {
		t.Skipf("Skipping test for unsupported OS %q", runtime.GOOS)
	}
	tests := []struct {
		name string
		path string
		want *homebrew.BrewPackage
	}{
		{
			name: "cellar_path",
			path: "testdata/Cellar/rclone/1.67.0/INSTALL_RECEIPT.json",
			want: &homebrew.BrewPackage{
				AppName:        "rclone",
				AppVersion:     "1.67.0",
				AppFile:        "install_receipt.json",
				AppExt:         "install_receipt.json",
				AppFormulaPath: "testdata/Cellar/rclone/1.67.0/.brew/rclone.rb",
			},
		},
		{
			name: "caskroom_path",
			path: "testdata/Caskroom/testapp/1.1.1/testapp.wrapper.sh",
			want: &homebrew.BrewPackage{
				AppName:    "testapp",
				AppVersion: "1.1.1",
				AppFile:    "testapp.wrapper.sh",
				AppExt:     "testapp.wrapper.sh",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := homebrew.SplitPath(tt.path)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("SpiltPath(%v) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
