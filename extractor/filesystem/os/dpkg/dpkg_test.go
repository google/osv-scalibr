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

package dpkg_test

import (
	"fmt"
	"io/fs"
	golog "log"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     dpkg.Config
		wantCfg dpkg.Config
	}{
		{
			name: "default",
			cfg:  dpkg.DefaultConfig(),
			wantCfg: dpkg.Config{
				MaxFileSizeBytes:    100 * units.MiB,
				IncludeNotInstalled: false,
			},
		},
		{
			name: "custom",
			cfg: dpkg.Config{
				MaxFileSizeBytes:    10,
				IncludeNotInstalled: true,
			},
			wantCfg: dpkg.Config{
				MaxFileSizeBytes:    10,
				IncludeNotInstalled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dpkg.New(tt.cfg)
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
			name:             "status file",
			path:             "var/lib/dpkg/status",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file in status.d",
			path:             "var/lib/dpkg/status.d/foo",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "ignore md5sums file",
			path:         "var/lib/dpkg/status.d/foo.md5sums",
			wantRequired: false,
		},
		{
			name:         "status.d as a file",
			path:         "var/lib/dpkg/status.d",
			wantRequired: false,
		},
		{
			name:             "status file required if file size < max file size",
			path:             "var/lib/dpkg/status",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "status file required if file size == max file size",
			path:             "var/lib/dpkg/status",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "status file not required if file size > max file size",
			path:             "var/lib/dpkg/status",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "status file required if max file size set to 0",
			path:             "var/lib/dpkg/status",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "status file",
			path:             "usr/lib/opkg/status",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "status as a directory",
			path:         "usr/lib/opkg/status/foo",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = dpkg.New(dpkg.Config{
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

const OpkgRelease = `NAME="OpenWrt"
VERSION="21.02.1"
ID=openwrt
VERSION_ID="21.02.1"
VERSION_CODENAME="openwrt-21.02.1"
PRETTY_NAME="OpenWrt 21.02.1"
BUILD_ID="r16279-5cc53c7f44"`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              dpkg.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
		wantLogWarn      int
		wantLogErr       int
	}{
		{
			name:      "valid status file",
			path:      "testdata/dpkg/valid",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "accountsservice",
					Version: "22.08.8-6",
					Metadata: &dpkg.Metadata{
						PackageName:       "accountsservice",
						PackageVersion:    "22.08.8-6",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Debian freedesktop.org maintainers <pkg-freedesktop-maintainers@lists.alioth.debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				{
					Name:    "adduser",
					Version: "3.131",
					Metadata: &dpkg.Metadata{
						PackageName:       "adduser",
						PackageVersion:    "3.131",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Debian Adduser Developers <adduser@packages.debian.org>",
						Architecture:      "all",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				{
					Name:    "admin-session",
					Version: "2023.06.26.c543406313-00",
					Metadata: &dpkg.Metadata{
						PackageName:       "admin-session",
						PackageVersion:    "2023.06.26.c543406313-00",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "nobody@google.com",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				{
					Name:    "attr",
					Version: "1:2.5.1-4",
					Metadata: &dpkg.Metadata{
						PackageName:       "attr",
						PackageVersion:    "1:2.5.1-4",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				// Expect source name.
				{
					Name:    "libacl1",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "libacl1",
						PackageVersion:    "2.3.1-3",
						Status:            "install ok installed",
						SourceName:        "acl",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
				// Expect source name and version.
				{
					Name:    "util-linux-extra",
					Version: "2.38.1-5+b1",
					Metadata: &dpkg.Metadata{
						PackageName:       "util-linux-extra",
						PackageVersion:    "2.38.1-5+b1",
						Status:            "install ok installed",
						SourceName:        "util-linux",
						SourceVersion:     "2.38.1-5",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "util-linux packagers <util-linux@packages.debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "packages with no version set are skipped",
			path:      "testdata/dpkg/noversion",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "foo",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/noversion"},
				},
				{
					Name:    "bar",
					Version: "2.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "bar",
						PackageVersion:    "2.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/noversion"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "packages with no name set are skipped",
			path:      "testdata/dpkg/nopackage",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "foo",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/nopackage"},
				},
				{
					Name:    "bar",
					Version: "2.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "bar",
						PackageVersion:    "2.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/nopackage"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "statusfield",
			path:      "testdata/dpkg/statusfield",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantdeinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantdeinstall_installed",
						PackageVersion:    "1.0",
						Status:            "deinstall reinstreq installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						Status:            "purge ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "statusfield including not installed",
			path:      "testdata/dpkg/statusfield",
			osrelease: DebianBookworm,
			cfg: dpkg.Config{
				IncludeNotInstalled: true,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantdeinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantdeinstall_installed",
						PackageVersion:    "1.0",
						Status:            "deinstall reinstreq installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantdeinstall_configfiles",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantdeinstall_configfiles",
						PackageVersion:    "1.0",
						Status:            "deinstall ok config-files",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantinstall_unpacked",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_unpacked",
						PackageVersion:    "1.0",
						Status:            "install ok unpacked",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						Status:            "purge ok installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantinstall_halfinstalled",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_halfinstalled",
						PackageVersion:    "1.0",
						Status:            "install reinstreq half-installed",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
				{
					Name:    "wantnostatus",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantnostatus",
						PackageVersion:    "1.0",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
					},
					Locations: []string{"testdata/dpkg/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/dpkg/empty",
			osrelease:        DebianBookworm,
			wantInventory:    []*extractor.Inventory{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/dpkg/invalid",
			osrelease:        DebianBookworm,
			wantInventory:    []*extractor.Inventory{},
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "VERSION_CODENAME not set, fallback to VERSION_ID",
			path: "testdata/dpkg/single",
			osrelease: `VERSION_ID="12"
			ID=debian`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:    "acl",
						PackageVersion: "2.3.1-3",
						Status:         "install ok installed",
						OSID:           "debian",
						OSVersionID:    "12",
						Maintainer:     "Guillem Jover <guillem@debian.org>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/dpkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no version",
			path:      "testdata/dpkg/single",
			osrelease: `ID=debian`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:    "acl",
						PackageVersion: "2.3.1-3",
						Status:         "install ok installed",
						OSID:           "debian",
						Maintainer:     "Guillem Jover <guillem@debian.org>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/dpkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "osrelease id not set",
			path:      "testdata/dpkg/single",
			osrelease: "VERSION_CODENAME=bookworm",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						Status:            "install ok installed",
						OSVersionCodename: "bookworm",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "ubuntu",
			path: "testdata/dpkg/single",
			osrelease: `VERSION_ID="22.04"
			VERSION_CODENAME=jammy
			ID=ubuntu
			ID_LIKE=debian`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						Status:            "install ok installed",
						OSID:              "ubuntu",
						OSVersionCodename: "jammy",
						OSVersionID:       "22.04",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "ubuntu",
			path: "testdata/dpkg/trailingnewlines",
			osrelease: `VERSION_ID="22.04"
			VERSION_CODENAME=jammy
			ID=ubuntu
			ID_LIKE=debian`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "acl",
					Version: "2.3.1-3",
					Metadata: &dpkg.Metadata{
						PackageName:       "acl",
						PackageVersion:    "2.3.1-3",
						Status:            "install ok installed",
						OSID:              "ubuntu",
						OSVersionCodename: "jammy",
						OSVersionID:       "22.04",
						Maintainer:        "Guillem Jover <guillem@debian.org>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/trailingnewlines"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      0,
			wantLogErr:       0,
		},
		{
			name:      "status.d file without Status field set should work",
			path:      "testdata/dpkg/status.d/foo",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "foo",
					Version: "1.2.3",
					Metadata: &dpkg.Metadata{
						PackageName:       "foo",
						PackageVersion:    "1.2.3",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "someone",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/dpkg/status.d/foo"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "status.d file without Status field set should work",
			path:             "testdata/dpkg/status.d/foo.md5sums",
			osrelease:        DebianBookworm,
			wantInventory:    []*extractor.Inventory{},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "transitional packages should be annotated",
			path:      "testdata/dpkg/transitional",
			osrelease: DebianBookworm,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "iceweasel",
					Version: "78.13.0esr-1~deb10u1",
					Metadata: &dpkg.Metadata{
						PackageName:       "iceweasel",
						Status:            "install ok installed",
						PackageVersion:    "78.13.0esr-1~deb10u1",
						SourceName:        "firefox-esr",
						OSID:              "debian",
						OSVersionCodename: "bookworm",
						OSVersionID:       "12",
						Maintainer:        "Maintainers of Mozilla-related packages <team+pkg-mozilla@tracker.debian.org>",
						Architecture:      "all",
					},
					Locations:   []string{"testdata/dpkg/transitional"},
					Annotations: []extractor.Annotation{extractor.Transitional},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "valid opkg status file",
			path:      "testdata/opkg/valid", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,           // You can mock the os-release data as needed
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/valid"},
				},
				{
					Name:    "libuci20130104",
					Version: "2023.08.10~5781664d-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "libuci20130104",
						PackageVersion:    "2023.08.10~5781664d-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/valid"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &dpkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "packages with no version set are skipped",
			path:      "testdata/opkg/noversion",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/noversion"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &dpkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/noversion"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "packages with no name set are skipped",
			path:      "testdata/opkg/nopackage",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/nopackage"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &dpkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/nopackage"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "statusfield",
			path:      "testdata/opkg/statusfield", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,                 // You can mock the os-release data as needed
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						Status:            "purge ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "statusfield including not installed",
			path:      "testdata/opkg/statusfield", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,                 // You can mock the os-release data as needed
			cfg: dpkg.Config{
				IncludeNotInstalled: true,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantdeinstall_configfiles",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantdeinstall_configfiles",
						PackageVersion:    "1.0",
						Status:            "deinstall ok config-files",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantinstall_unpacked",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantinstall_unpacked",
						PackageVersion:    "1.0",
						Status:            "install ok unpacked",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						Status:            "purge ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantpurge_notinstalled",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantpurge_notinstalled",
						PackageVersion:    "1.0",
						Status:            "purge ok not-installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
				{
					Name:    "wantnostatus",
					Version: "1.0",
					Metadata: &dpkg.Metadata{
						PackageName:       "wantnostatus",
						PackageVersion:    "1.0",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/opkg/empty",
			osrelease:        OpkgRelease,
			wantInventory:    []*extractor.Inventory{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/opkg/invalid",
			osrelease:        OpkgRelease,
			wantInventory:    []*extractor.Inventory{},
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "VERSION_CODENAME not set, fallback to VERSION_ID",
			path: "testdata/opkg/single",
			osrelease: `VERSION_ID="21.02.1"
			ID=openwrt`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:    "ubus",
						PackageVersion: "2024.10.20~252a9b0c-r1",
						Status:         "install ok installed",
						Architecture:   "x86_64",
						OSID:           "openwrt",
						OSVersionID:    "21.02.1",
					},
					Locations: []string{"testdata/opkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no version",
			path:      "testdata/opkg/single",
			osrelease: `ID=openwrt`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:    "ubus",
						PackageVersion: "2024.10.20~252a9b0c-r1",
						Status:         "install ok installed",
						Architecture:   "x86_64",
						OSID:           "openwrt",
					},
					Locations: []string{"testdata/opkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "osrelease id not set",
			path:      "testdata/opkg/single",
			osrelease: `VERSION_CODENAME=openwrt-21.02.1`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSVersionCodename: "openwrt-21.02.1",
					},
					Locations: []string{"testdata/opkg/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "newlines",
			path:      "testdata/opkg/trailingnewlines",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/opkg/trailingnewlines"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      0,
			wantLogErr:       0,
		},
		{
			name:      "transitional packages should be annotated",
			path:      "testdata/opkg/transitional",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &dpkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations:   []string{"testdata/opkg/transitional"},
					Annotations: []extractor.Annotation{extractor.Transitional},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			logger := &testLogger{}
			scalibrlog.SetLogger(logger)

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

			input := &filesystem.ScanInput{
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Root: d, Info: info,
			}

			e := dpkg.New(defaultConfigWith(tt.cfg))
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

			if logger.warnings != tt.wantLogWarn {
				t.Errorf("Extract(%s) recorded %d warnings, want %d warnings", tt.path, logger.warnings, tt.wantLogWarn)
			}
			if logger.errors != tt.wantLogErr {
				t.Errorf("Extract(%s) recorded %d errors, want %d errors", tt.path, logger.errors, tt.wantLogErr)
			}
		})
	}
}

var _ scalibrlog.Logger = &testLogger{}

type testLogger struct {
	Verbose  bool
	warnings int
	errors   int
}

// Errorf is the formatted error logging function.
func (l *testLogger) Errorf(format string, args ...any) {
	golog.Printf(format, args...)
	l.errors++
}

// Warnf is the formatted warning logging function.
func (l *testLogger) Warnf(format string, args ...any) {
	golog.Printf(format, args...)
	l.warnings++
}

// Infof is the formatted info logging function.
func (testLogger) Infof(format string, args ...any) {
	golog.Printf(format, args...)
}

// Debugf is the formatted debug logging function.
func (l *testLogger) Debugf(format string, args ...any) {
	if l.Verbose {
		golog.Printf(format, args...)
	}
}

// Error is the error logging function.
func (l *testLogger) Error(args ...any) {
	golog.Println(args...)
	l.errors++
}

// Warn is the warning logging function.
func (l *testLogger) Warn(args ...any) {
	golog.Println(args...)
	l.warnings++
}

// Info is the info logging function.
func (testLogger) Info(args ...any) {
	golog.Println(args...)
}

// Debug is the debug logging function.
func (l *testLogger) Debug(args ...any) {
	if l.Verbose {
		golog.Println(args...)
	}
}

func TestExtractNonexistentOSRelease(t *testing.T) {
	path := "testdata/dpkg/single"

	want := []*extractor.Inventory{
		{
			Name:    "acl",
			Version: "2.3.1-3",
			Metadata: &dpkg.Metadata{
				PackageName:    "acl",
				PackageVersion: "2.3.1-3",
				Status:         "install ok installed",
				OSID:           "",
				OSVersionID:    "",
				Maintainer:     "Guillem Jover <guillem@debian.org>",
				Architecture:   "amd64",
			},
			Locations: []string{path},
		},
	}

	r, err := os.Open(path)
	defer func() {
		if err = r.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Note that we didn't create any OS release file.
	input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: path, Info: info, Reader: r}

	e := dpkg.New(dpkg.DefaultConfig())
	got, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract(%s) error: %v", path, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Extract(%s) (-want +got):\n%s", path, diff)
	}
}

func TestToPURL(t *testing.T) {
	pkgname := "pkgname"
	sourcename := "sourcename"
	version := "1.2.3"
	sourceversion := "1.2.4"
	source := "sourcename"
	e := dpkg.Extractor{}
	tests := []struct {
		name     string
		location string
		metadata *dpkg.Metadata
		want     *purl.PackageURL
	}{
		{
			name:     "both OS versions present",
			location: "var/lib/dpkg/status",
			metadata: &dpkg.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSID:              "debian",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			name:     "only VERSION_ID set",
			location: "var/lib/dpkg/status",
			metadata: &dpkg.Metadata{
				PackageName:   pkgname,
				SourceName:    sourcename,
				SourceVersion: sourceversion,
				OSID:          "debian",
				OSVersionID:   "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "22.04",
				}),
			},
		},
		{
			name:     "ID not set, fallback to linux",
			location: "var/lib/dpkg/status",
			metadata: &dpkg.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			name:     "OS ID and OS Version set (OpenWrt)",
			location: "usr/lib/opkg/status",
			metadata: &dpkg.Metadata{
				PackageName: pkgname,
				OSID:        "openwrt",
				OSVersionID: "22.03.5",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "openwrt",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.03.5",
				}),
			},
		},
		{
			name:     "OS ID not set, fallback to linux",
			location: "usr/lib/opkg/status",
			metadata: &dpkg.Metadata{
				PackageName:       pkgname,
				OSVersionCodename: "jammy",
				OSVersionID:       "5.10",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			i := &extractor.Inventory{
				Name:      pkgname,
				Version:   version,
				Metadata:  tt.metadata,
				Locations: []string{tt.location},
			}
			got := e.ToPURL(i)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
			}
		})
	}
}

func TestEcosystem(t *testing.T) {
	e := dpkg.Extractor{}
	tests := []struct {
		name     string
		metadata *dpkg.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &dpkg.Metadata{
				OSID: "debian",
			},
			want: "Debian",
		},
		{
			name:     "OS ID not present",
			metadata: &dpkg.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &dpkg.Metadata{
				OSID:        "debian",
				OSVersionID: "12",
			},
			want: "Debian:12",
		},
		{
			name: "OS ID present (OpenWrt)",
			metadata: &dpkg.Metadata{
				OSID: "openwrt",
			},
			want: "Openwrt",
		},
		{
			name: "OS version present (OpenWrt)",
			metadata: &dpkg.Metadata{
				OSID:        "openwrt",
				OSVersionID: "22.03.5",
			},
			want: "Openwrt:22.03.5",
		},
		{
			name: "OS version present (Generic Linux)",
			metadata: &dpkg.Metadata{
				OSID:        "linux",
				OSVersionID: "5",
			},
			want: "Linux:5",
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

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg dpkg.Config) dpkg.Config {
	newCfg := dpkg.DefaultConfig()

	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}

	if cfg.IncludeNotInstalled {
		newCfg.IncludeNotInstalled = cfg.IncludeNotInstalled
	}

	return newCfg
}
