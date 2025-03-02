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

package flatpak_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/flatpak"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
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
			name:             "metainfo xml file required if in global flatpak metainfo dir",
			path:             "var/lib/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "metainfo xml file required if in user local flatpak metainfo dir",
			path:             "home/testuser/.local/share/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "metainfo xml file required if file size < max file size",
			path:             "var/lib/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "metainfo xml file required if file size == max file size",
			path:             "var/lib/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "metainfo xml file not required if file size > max file size",
			path:             "var/lib/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "metainfo xml file required if max file size = 0",
			path:             "var/lib/flatpak/app/org.gimp.GIMP/current/export/share/metainfo/org.gimp.GIMP.metainfo.xml",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "xml file not required if not in flatpak metainfo dir",
			path:         "var/lib/xml-dir/metadata.xml",
			wantRequired: false,
		},
		{
			name:         "some other file in flatpak metainfo dir not required",
			path:         "var/lib/flatpak/exports/share/metainfo/test.txt",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = flatpak.New(flatpak.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
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

const DebianBookworm = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              flatpak.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid metainfo xml file is extracted",
			path:      "testdata/valid.xml",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "org.gimp.GIMP",
					Version: "2.10.38",
					Metadata: &flatpak.Metadata{
						PackageName:    "GNU Image Manipulation Program",
						PackageID:      "org.gimp.GIMP",
						PackageVersion: "2.10.38",
						ReleaseDate:    "2024-05-02",
						OSID:           "debian",
						OSVersionID:    "12",
						OSName:         "Debian GNU/Linux",
						Developer:      "The GIMP team",
					},
					Locations: []string{"testdata/valid.xml"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "metainfo xml file without package name is extracted",
			path:      "testdata/noname.xml",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "org.gimp.GIMP",
					Version: "2.10.38",
					Metadata: &flatpak.Metadata{
						PackageName:    "",
						PackageID:      "org.gimp.GIMP",
						PackageVersion: "2.10.38",
						ReleaseDate:    "2024-05-02",
						OSID:           "debian",
						OSVersionID:    "12",
						OSName:         "Debian GNU/Linux",
						Developer:      "The GIMP team",
					},
					Locations: []string{"testdata/noname.xml"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "metainfo xml file without package version is skipped",
			path:             "testdata/noversion.xml",
			osrelease:        DebianBookworm,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "malformed metainfo xml file is skipped",
			path:             "testdata/bad.xml",
			osrelease:        DebianBookworm,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			tt.cfg.Stats = collector

			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

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

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info}

			e := flatpak.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	pkgname := "pkgname"
	pkgid := "pkgid"
	pkgversion := "1.2.3"
	releasedate := "2024-05-02"
	osname := "Debian GNU/Linux"
	osid := "debian"
	osversionid := "12"
	osbuildid := "bookworm"
	developer := "developer"
	e := flatpak.Extractor{}
	tests := []struct {
		name     string
		metadata *flatpak.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "Both VERSION_ID and BUILD_ID is set",
			metadata: &flatpak.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSID:           osid,
				OSVersionID:    osversionid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "debian",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "debian-12",
				}),
			},
		},
		{
			name: "only BUILD_ID set",
			metadata: &flatpak.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSID:           osid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "debian",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "debian-bookworm",
				}),
			},
		},
		{
			name: "OS_ID not set",
			metadata: &flatpak.Metadata{
				PackageName:    pkgname,
				PackageID:      pkgid,
				PackageVersion: pkgversion,
				ReleaseDate:    releasedate,
				OSName:         osname,
				OSVersionID:    osversionid,
				OSBuildID:      osbuildid,
				Developer:      developer,
			},
			want: &purl.PackageURL{
				Type:      purl.TypeFlatpak,
				Name:      pkgname,
				Namespace: "",
				Version:   pkgversion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "12",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      pkgname,
				Version:   pkgversion,
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

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg flatpak.Config) flatpak.Config {
	newCfg := flatpak.DefaultConfig()

	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}

	return newCfg
}
