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

package chisel_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
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
			name:             "manifest json wall file",
			path:             "var/lib/chisel/manifest.wall",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "manifest.wall file not in desired location",
			path:         "manifest.wall",
			wantRequired: false,
		},
		{
			name:             "manifest.wall file exceeds max file size",
			path:             "var/lib/chisel/manifest.wall",
			fileSizeBytes:    1024 * units.MiB,
			maxFileSizeBytes: 100 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := chisel.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("chisel.New: %v", err)
			}
			e.(*chisel.Extractor).Stats = collector

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

const UbuntuNoble = `PRETTY_NAME="Ubuntu 24.04.2 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.2 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              *cpb.PluginConfig
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid manifest wall file",
			path:      "testdata/chisel/openssl.wall",
			osrelease: UbuntuNoble,
			wantPackages: []*extractor.Package{
				{
					Name:    "base-files",
					Version: "13ubuntu10.2",
					Metadata: &dpkgmeta.Metadata{
						PackageName:       "base-files",
						PackageVersion:    "13ubuntu10.2",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/openssl.wall"),
					PURLType: purl.TypeDebian,
				},
				{
					Name:    "libc6",
					Version: "2.39-0ubuntu8.4",
					Metadata: &dpkgmeta.Metadata{
						PackageName:       "libc6",
						PackageVersion:    "2.39-0ubuntu8.4",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/openssl.wall"),
					PURLType: purl.TypeDebian,
				},
				{
					Name:    "libssl3t64",
					Version: "3.0.13-0ubuntu3.5",
					Metadata: &dpkgmeta.Metadata{
						PackageName:       "libssl3t64",
						PackageVersion:    "3.0.13-0ubuntu3.5",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/openssl.wall"),
					PURLType: purl.TypeDebian,
				},
				{
					Name:    "openssl",
					Version: "3.0.13-0ubuntu3.5",
					Metadata: &dpkgmeta.Metadata{
						PackageName:       "openssl",
						PackageVersion:    "3.0.13-0ubuntu3.5",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/openssl.wall"),
					PURLType: purl.TypeDebian,
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},

		{
			name:             "empty",
			path:             "testdata/chisel/empty.wall",
			osrelease:        UbuntuNoble,
			wantPackages:     []*extractor.Package{},
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "invalid",
			path:             "testdata/chisel/invalid.wall",
			osrelease:        UbuntuNoble,
			wantPackages:     []*extractor.Package{},
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "VERSION_CODENAME not set, fallback to VERSION_ID",
			path: "testdata/chisel/single.wall",
			osrelease: `VERSION_ID="24.04"
			ID=ubuntu`,
			wantPackages: []*extractor.Package{
				{
					Name:    "base-files",
					Version: "13ubuntu10.2",
					Metadata: &dpkgmeta.Metadata{
						PackageName:    "base-files",
						PackageVersion: "13ubuntu10.2",
						OSID:           "ubuntu",
						OSVersionID:    "24.04",
						Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:   "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/single.wall"),
					PURLType: purl.TypeDebian,
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no version",
			path:      "testdata/chisel/single.wall",
			osrelease: `ID=ubuntu`,
			wantPackages: []*extractor.Package{
				{
					Name:    "base-files",
					Version: "13ubuntu10.2",
					Metadata: &dpkgmeta.Metadata{
						PackageName:    "base-files",
						PackageVersion: "13ubuntu10.2",
						OSID:           "ubuntu",
						Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:   "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/single.wall"),
					PURLType: purl.TypeDebian,
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "osrelease id not set",
			path:      "testdata/chisel/single.wall",
			osrelease: "VERSION_CODENAME=noble",
			wantPackages: []*extractor.Package{
				{
					Name:    "base-files",
					Version: "13ubuntu10.2",
					Metadata: &dpkgmeta.Metadata{
						PackageName:       "base-files",
						PackageVersion:    "13ubuntu10.2",
						OSVersionCodename: "noble",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Location: extractor.LocationFromPath("testdata/chisel/single.wall"),
					PURLType: purl.TypeDebian,
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()

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

			cfg := tt.cfg
			if cfg == nil {
				cfg = &cpb.PluginConfig{}
			}
			e, err := chisel.New(cfg)
			if err != nil {
				t.Fatalf("chisel.New: %v", err)
			}
			e.(*chisel.Extractor).Stats = collector
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
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

func TestExtractNonexistentOSRelease(t *testing.T) {
	path := "testdata/chisel/single.wall"

	want := inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:    "base-files",
			Version: "13ubuntu10.2",
			Metadata: &dpkgmeta.Metadata{
				PackageName:    "base-files",
				PackageVersion: "13ubuntu10.2",
				OSID:           "",
				OSVersionID:    "",
				Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
				Architecture:   "amd64",
			},
			Location: extractor.LocationFromPath(path),
			PURLType: purl.TypeDebian,
		},
	}}

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

	e, err := chisel.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("chisel.New: %v", err)
	}
	got, err := e.Extract(t.Context(), input)
	if err != nil {
		t.Fatalf("Extract(%s) error: %v", path, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Extract(%s) (-want +got):\n%s", path, diff)
	}
}

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
