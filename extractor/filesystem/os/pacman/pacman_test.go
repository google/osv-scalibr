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

package pacman_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     pacman.Config
		wantCfg pacman.Config
	}{
		{
			name: "default",
			cfg:  pacman.DefaultConfig(),
			wantCfg: pacman.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: pacman.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: pacman.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pacman.New(tt.cfg)
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
			name:             "desc file",
			path:             "var/lib/pacman/local/pacmanlinux-keyring-20241015-1/desc",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "desc file required if file size < max file size",
			path:             "var/lib/pacman/local/argon2-20190702-6/desc",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "desc file required if file size == max file size",
			path:             "var/lib/pacman/local/audit-4.0.2-2/desc",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "desc file not required if file size > max file size",
			path:             "var/lib/pacman/local/argon2-20190702-6/desc",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "desc file required if max file size set to 0",
			path:             "var/lib/pacman/local/audit-4.0.2-2/desc",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "invalid file",
			path:         "var/lib/pacman/local/pacmanlinux-keyring-20241015-1/foodesc",
			wantRequired: false,
		},
		{
			name:         "invalid file",
			path:         "var/lib/pacman/local/pacmanlinux-keyring-20241015-1/desc/foo",
			wantRequired: false,
		},
		{
			name:         "invalid file",
			path:         "var/lib/pacman/localfoo/desc",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = pacman.New(pacman.Config{
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

const ArchRolling = `NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
VERSION_ID=20241201.0.284684
ANSI_COLOR="38;2;23;147;209"
HOME_URL="https://archlinux.org/"
DOCUMENTATION_URL="https://wiki.archlinux.org/"
SUPPORT_URL="https://bbs.archlinux.org/"
BUG_REPORT_URL="https://gitlab.archlinux.org/groups/archlinux/-/issues"
PRIVACY_POLICY_URL="https://terms.archlinux.org/docs/privacy-policy/"
LOGO=archlinux-logo
`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              pacman.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid desc file",
			path:      "testdata/valid",
			osrelease: ArchRolling,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "gawk",
					Version: "5.3.1-1",
					Metadata: &pacman.Metadata{
						PackageName:         "gawk",
						PackageVersion:      "5.3.1-1",
						OSID:                "arch",
						OSVersionID:         "20241201.0.284684",
						PackageDependencies: "sh, glibc, mpfr",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid desc file one dependency",
			path:      "testdata/valid_one_dep",
			osrelease: ArchRolling,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "filesystem",
					Version: "2024.11.21-1",
					Metadata: &pacman.Metadata{
						PackageName:         "filesystem",
						PackageVersion:      "2024.11.21-1",
						OSID:                "arch",
						OSVersionID:         "20241201.0.284684",
						PackageDependencies: "iana-etc",
					},
					Locations: []string{"testdata/valid_one_dep"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid desc file no dependencies",
			path:      "testdata/valid_no_dep",
			osrelease: ArchRolling,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "libxml2",
					Version: "2.13.5-1",
					Metadata: &pacman.Metadata{
						PackageName:    "libxml2",
						PackageVersion: "2.13.5-1",
						OSID:           "arch",
						OSVersionID:    "20241201.0.284684",
					},
					Locations: []string{"testdata/valid_no_dep"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no os version",
			path:      "testdata/valid",
			osrelease: `ID=arch`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "gawk",
					Version: "5.3.1-1",
					Metadata: &pacman.Metadata{
						PackageName:         "gawk",
						PackageVersion:      "5.3.1-1",
						OSID:                "arch",
						PackageDependencies: "sh, glibc, mpfr",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "missing osrelease",
			path: "testdata/valid",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "gawk",
					Version: "5.3.1-1",
					Metadata: &pacman.Metadata{
						PackageName:         "gawk",
						PackageVersion:      "5.3.1-1",
						PackageDependencies: "sh, glibc, mpfr",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:          "invalid value eof",
			path:          "testdata/invalid_value_eof",
			osrelease:     ArchRolling,
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:      "eof after dependencies",
			path:      "testdata/eof_after_dependencies",
			osrelease: ArchRolling,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "gawk",
					Version: "5.3.1-1",
					Metadata: &pacman.Metadata{
						PackageName:         "gawk",
						PackageVersion:      "5.3.1-1",
						OSID:                "arch",
						OSVersionID:         "20241201.0.284684",
						PackageDependencies: "sh, glibc, mpfr",
					},
					Locations: []string{"testdata/eof_after_dependencies"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = pacman.New(pacman.Config{
				Stats:            collector,
				MaxFileSizeBytes: 100,
			})

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

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

			if diff := cmp.Diff(tt.wantInventory, got); diff != "" {
				t.Errorf("Inventory mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"
	PackageDependencies := "pkgDependencies1, pkgDependencies2"

	e := pacman.Extractor{}
	tests := []struct {
		name     string
		metadata *pacman.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &pacman.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSID:                "arch",
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "arch",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &pacman.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSID:                "arch",
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "arch",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
		{
			name: "OS ID not set, fallback to Linux",
			metadata: &pacman.Metadata{
				PackageName:         pkgName,
				PackageVersion:      pkgVersion,
				OSVersionID:         "20241201.0.284684",
				PackageDependencies: PackageDependencies,
			},
			want: &purl.PackageURL{
				Type:      purl.TypePacman,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro:              "20241201.0.284684",
					purl.PackageDependencies: PackageDependencies,
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      pkgName,
				Version:   pkgVersion,
				Metadata:  tt.metadata,
				Locations: []string{"location"},
			}
			got := e.ToPURL(i)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
			}
		})
	}
}

func TestEcosystem(t *testing.T) {
	e := pacman.Extractor{}
	tests := []struct {
		name     string
		metadata *pacman.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &pacman.Metadata{
				OSID: "arch",
			},
			want: "Arch",
		},
		{
			name:     "OS ID not present",
			metadata: &pacman.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &pacman.Metadata{
				OSID:        "arch",
				OSVersionID: "20241201.0.284684",
			},
			want: "Arch:20241201.0.284684",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Metadata: tt.metadata,
			}
			got := e.Ecosystem(i)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Ecosystem(%v) (-want +got):\n%s", i, diff)
			}
		})
	}
}

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
