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

package chocolatey_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey"
	chocolateymeta "github.com/google/osv-scalibr/extractor/filesystem/os/chocolatey/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     chocolatey.Config
		wantCfg chocolatey.Config
	}{
		{
			name: "default",
			cfg:  chocolatey.DefaultConfig(),
			wantCfg: chocolatey.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: chocolatey.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: chocolatey.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chocolatey.New(tt.cfg)
			if !reflect.DeepEqual(got.Config(), tt.wantCfg) {
				t.Errorf("New(%+v).Config(): got %+v, want %+v", tt.cfg, got.Config(), tt.wantCfg)
			}
		})
	}
}

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
			name:             "nuspec file",
			path:             "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "nuspec file required if file size < max file size",
			path:             "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "nuspec file required if file size == max file size",
			path:             "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "nuspec file not required if file size > max file size",
			path:             "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "nuspec file required if max file size set to 0",
			path:             "/ProgramData/chocolatey/lib/vscode/vscode.nuspec",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "invalid file extension",
			path:         "/ProgramData/chocolatey/lib/vscode/vscode.nuspecrandom",
			wantRequired: false,
		},
		{
			name:         "invalid folder",
			path:         "/ProgramData/chocolatey/lib-bad/vscode/vscode.nuspec",
			wantRequired: false,
		},
		{
			name:         "invalid file",
			path:         "/ProgramData/choco.exe",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = chocolatey.New(chocolatey.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

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
	tests := []struct {
		name             string
		path             string
		cfg              chocolatey.Config
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid nuspec file",
			path: "testdata/chocolatey/lib/atom/atom.nuspec",
			wantPackages: []*extractor.Package{
				{
					Name:     "atom",
					Version:  "1.60.0",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "atom",
						Version:    "1.60.0",
						Authors:    "GitHub Inc.",
						Summary:    "A hackable text editor for the 21st Century.",
						LicenseURL: "https://github.com/atom/atom/blob/master/LICENSE.md",
						ProjectURL: "https://atom.io/",
						Tags:       "atom admin text editor notepad github package autocompletion",
					},
					Locations: []string{"testdata/chocolatey/lib/atom/atom.nuspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "valid nuspec file for install dependency",
			path: "testdata/chocolatey/lib/atom.install/atom.install.nuspec",
			wantPackages: []*extractor.Package{
				{
					Name:     "atom.install",
					Version:  "1.60.0",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "atom.install",
						Version:    "1.60.0",
						Authors:    "GitHub Inc.",
						Summary:    "A hackable text editor for the 21st Century.",
						LicenseURL: "https://github.com/atom/atom/blob/master/LICENSE.md",
						ProjectURL: "https://atom.io/",
						Tags:       "atom admin text editor notepad github package autocompletion",
					},
					Locations: []string{"testdata/chocolatey/lib/atom.install/atom.install.nuspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "missing tags field in a valid nuspec file",
			path: "testdata/chocolatey/lib/cmake/cmake.nuspec",
			wantPackages: []*extractor.Package{
				{
					Name:     "cmake",
					Version:  "4.1.1",
					PURLType: purl.TypeChocolatey,
					Metadata: &chocolateymeta.Metadata{
						Name:       "cmake",
						Version:    "4.1.1",
						Authors:    "Andy Cedilnik, Bill Hoffman, Brad King, Ken Martin, Alexander Neundorf",
						Summary:    "Cross-platform, open-source build system including CMake, CTest, CPack, and CMake-GUI",
						LicenseURL: "https://gitlab.kitware.com/cmake/cmake/blob/master/Copyright.txt",
						ProjectURL: "https://www.cmake.org/",
						Tags:       "",
					},
					Locations: []string{"testdata/chocolatey/lib/cmake/cmake.nuspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:         "missing id field in an unvalid nuspec file",
			path:         "testdata/chocolatey/lib/atom/atom_withoutid.nuspec",
			wantPackages: []*extractor.Package{},
		},
		{
			name:         "missing version field in an unvalid nuspec file",
			path:         "testdata/chocolatey/lib/atom/atom_withoutversion.nuspec",
			wantPackages: []*extractor.Package{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = chocolatey.New(chocolatey.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100,
			})

			d := t.TempDir()

			// Opening and Reading the Test File
			r, err := os.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info,
			}

			got, err := e.Extract(t.Context(), input)

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("Package mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
