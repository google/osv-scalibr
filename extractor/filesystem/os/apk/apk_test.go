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

package apk_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
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
			name:             "installed file",
			path:             "lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file in /usr",
			path:             "usr/lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file in /var",
			path:             "var/lib/apk/db/installed",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "sub file",
			path:         "lib/apk/db/installed/test",
			wantRequired: false,
		},
		{
			name:         "inside other dir",
			path:         "foo/lib/apk/db/installed",
			wantRequired: false,
		},
		{
			name:             "installed file required if file size < max file size",
			path:             "lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file required if file size == max file size",
			path:             "lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "installed file not required if file size > max file size",
			path:             "lib/apk/db/installed",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "installed file required if max file size set to 0",
			path:             "lib/apk/db/installed",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = apk.New(apk.Config{
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

const alpine = `NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.18.0
PRETTY_NAME="Alpine Linux v3.18"
HOME_URL="https://alpinelinux.org/"
BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "alpine latest",
			path:      "testdata/installed",
			osrelease: alpine,
			wantPackages: []*extractor.Package{
				getPackage("testdata/installed", "alpine-baselayout", "alpine-baselayout", "3.4.3-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
				getPackage("testdata/installed", "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
				getPackage("testdata/installed", "alpine-keys", "alpine-keys", "2.4-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "MIT", "aab68f8c9ab434a46710de8e12fb3206e2930a59"),
				getPackage("testdata/installed", "apk-tools", "apk-tools", "2.14.0-r0", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "028d34f678a5386c3dc488cc3b62467c7a9d1a0b"),
				getPackage("testdata/installed", "busybox", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only", "b5c719c244319df3c72ab1f1ee994c2143cab7f0"),
				getPackage("testdata/installed", "busybox-binsh", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only", "b5c719c244319df3c72ab1f1ee994c2143cab7f0"),
				getPackage("testdata/installed", "ca-certificates-bundle", "ca-certificates", "20230506-r0", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "MPL-2.0 AND MIT", "59534a02716a92a10d177a118c34066162eff4a6"),
				getPackage("testdata/installed", "libc-utils", "libc-dev", "0.7.2-r5", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "BSD-2-Clause AND BSD-3-Clause", "988f183cc9d6699930c3e18ccf4a9e36010afb56"),
				getPackage("testdata/installed", "libcrypto3", "openssl", "3.1.0-r4", "alpine", "3.18.0", "Ariadne Conill <ariadne@dereferenced.org>", "x86_64", "Apache-2.0", "730b75e01c670e3dba5d6c05420b5f605edb6201"),
				getPackage("testdata/installed", "libssl3", "openssl", "3.1.0-r4", "alpine", "3.18.0", "Ariadne Conill <ariadne@dereferenced.org>", "x86_64", "Apache-2.0", "730b75e01c670e3dba5d6c05420b5f605edb6201"),
				getPackage("testdata/installed", "musl", "musl", "1.2.4-r0", "alpine", "3.18.0", "Timo Teräs <timo.teras@iki.fi>", "x86_64", "MIT", "b0d8a9d948174e28a4aefcee4ef6be872225ccce"),
				getPackage("testdata/installed", "musl-utils", "musl", "1.2.4-r0", "alpine", "3.18.0", "Timo Teräs <timo.teras@iki.fi>", "x86_64", "MIT AND BSD-2-Clause AND GPL-2.0-or-later", "b0d8a9d948174e28a4aefcee4ef6be872225ccce"),
				getPackage("testdata/installed", "scanelf", "pax-utils", "1.3.7-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "84a227baf001b6e0208e3352b294e4d7a40e93de"),
				getPackage("testdata/installed", "ssl_client", "busybox", "1.36.0-r9", "alpine", "3.18.0", "Sören Tempel <soeren+alpine@soeren-tempel.net>", "x86_64", "GPL-2.0-only", "b5c719c244319df3c72ab1f1ee994c2143cab7f0"),
				getPackage("testdata/installed", "zlib", "zlib", "1.2.13-r1", "alpine", "3.18.0", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "Zlib", "84a227baf001b6e0208e3352b294e4d7a40e93de"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "origin not set",
			path:      "testdata/no-origin",
			osrelease: alpine,
			wantPackages: []*extractor.Package{
				getPackage("testdata/no-origin", "pkgname", "", "1.2.3", "alpine", "3.18.0", "", "x86_64", "GPL-2.0-only", ""),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/empty",
			wantPackages:     []*extractor.Package{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid",
			wantPackages:     nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "osrelease_openwrt",
			path: "testdata/single",
			osrelease: `ID=openwrt
			VERSION_ID=1.2.3`,
			wantPackages: []*extractor.Package{
				getPackage("testdata/single", "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "openwrt", "1.2.3", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "osrelease no version",
			path:      "testdata/single",
			osrelease: "ID=openwrt",
			wantPackages: []*extractor.Package{
				getPackage("testdata/single", "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "openwrt", "", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no osrelease",
			path:      "testdata/single",
			osrelease: "",
			wantPackages: []*extractor.Package{
				getPackage("testdata/single", "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "", "", "Natanael Copa <ncopa@alpinelinux.org>", "x86_64", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "different arch",
			path:      "testdata/different-arch",
			osrelease: "",
			wantPackages: []*extractor.Package{
				getPackage("testdata/different-arch", "alpine-baselayout-data", "alpine-baselayout", "3.4.3-r1", "", "", "Natanael Copa <ncopa@alpinelinux.org>", "noarch", "GPL-2.0-only", "65502ca9379dd29d1ac4b0bf0dcf03a3dd1b324a"),
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = apk.New(apk.Config{
				Stats: collector,
			})

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

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS(d),
				Path:   tt.path,
				Reader: r,
				Root:   d,
				Info:   info,
			}

			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got, ignoreOrder); diff != "" {
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

func getPackage(path, pkgName, origin, version, osID, osVersionID, maintainer, arch, license string, commit string) *extractor.Package {
	p := &extractor.Package{
		Locations: []string{path},
		Name:      pkgName,
		Version:   version,
		PURLType:  purl.TypeApk,
		Metadata: &apkmeta.Metadata{
			PackageName:  pkgName,
			OriginName:   origin,
			OSID:         osID,
			OSVersionID:  osVersionID,
			Maintainer:   maintainer,
			Architecture: arch,
		},
		Licenses: []string{license},
	}
	if commit != "" {
		p.SourceCode = &extractor.SourceCodeIdentifier{
			Commit: commit,
		}
	}
	return p
}

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
