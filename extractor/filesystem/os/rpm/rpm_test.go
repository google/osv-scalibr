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

package rpm_test

import (
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestFileRequired(t *testing.T) {
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		// BDB
		{path: "usr/lib/sysimage/rpm/Packages", wantRequired: true},
		{path: "var/lib/rpm/Packages", wantRequired: true},
		{path: "usr/share/rpm/Packages", wantRequired: true},
		// NDB
		{path: "usr/lib/sysimage/rpm/Packages.db", wantRequired: true},
		{path: "var/lib/rpm/Packages.db", wantRequired: true},
		{path: "usr/share/rpm/Packages.db", wantRequired: true},
		// SQLite3
		{path: "usr/lib/sysimage/rpm/rpmdb.sqlite", wantRequired: true},
		{path: "var/lib/rpm/rpmdb.sqlite", wantRequired: true},
		{path: "usr/share/rpm/rpmdb.sqlite", wantRequired: true},
		// invalid
		{path: "rpm/rpmdb.sqlite", wantRequired: false},
		{path: "rpm/Packages.db", wantRequired: false},
		{path: "rpm/Packages", wantRequired: false},
		{path: "foo/var/lib/rpm/rpmdb.sqlite", wantRequired: false},
		{path: "foo/var/lib/rpm/Packages", wantRequired: false},
		{path: "/rpm/rpmdb.sqlite", wantRequired: false},
		{path: "/rpm/Packages.db", wantRequired: false},
		{path: "/rpm/Packages", wantRequired: false},
		{path: "/foo/var/lib/rpm/rpmdb.sqlite", wantRequired: false},
		{path: "/foo/var/lib/rpm/Packages", wantRequired: false},
		// File size limits
		{
			name:             "Packages file required if file size < max file size",
			path:             "usr/lib/sysimage/rpm/Packages",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Packages file required if file size == max file size",
			path:             "usr/lib/sysimage/rpm/Packages",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "Packages file not required if file size > max file size",
			path:             "usr/lib/sysimage/rpm/Packages",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "Packages file required if max file size set to 0",
			path:             "usr/lib/sysimage/rpm/Packages",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		desc := tt.name
		if desc == "" {
			desc = tt.path
		}

		t.Run(desc, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = rpm.New(rpm.Config{
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

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && tt.wantRequired {
				wantResultMetric = stats.FileRequiredResultOK
			}
			gotResultMetric := collector.FileRequiredResult(tt.path)
			if wantResultMetric != "" && gotResultMetric != wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, wantResultMetric)
			}
		})
	}
}

const fedora38 = `NAME="Fedora Linux"
VERSION="38 (Container Image)"
ID=fedora
VERSION_ID=38
VERSION_CODENAME=""
PLATFORM_ID="platform:f38"
PRETTY_NAME="Fedora Linux 38 (Container Image)"
CPE_NAME="cpe:/o:fedoraproject:fedora:38"
DEFAULT_HOSTNAME="fedora"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=38
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=38
SUPPORT_END=2024-05-14
VARIANT="Container Image"`

func TestExtract(t *testing.T) {
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name       string
		path       string
		osrelease  string
		timeoutval time.Duration
		// rpm -qa --qf "%{NAME}@%{VERSION}-%{RELEASE}\n" |sort |head -n 3
		wantInventory []*extractor.Inventory
		// rpm -qa | wc -l
		wantResults      int
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "opensuse/leap:15.5 Packages.db file (NDB)",
			// docker run --rm --entrypoint cat opensuse/leap:15.5 /var/lib/rpm/Packages.db > third_party/scalibr/extractor/filesystem/os/rpm/testdata/Packages.db
			path:             "testdata/Packages.db",
			osrelease:        fedora38,
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "aaa_base",
					Version:   "84.87+git20180409.04c9dae-150300.10.3.1",
					Metadata: &rpm.Metadata{
						PackageName:  "aaa_base",
						Epoch:        0,
						SourceRPM:    "aaa_base-84.87+git20180409.04c9dae-150300.10.3.1.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-2.0+",
					},
				},
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "bash",
					Version:   "4.4-150400.25.22",
					Metadata: &rpm.Metadata{
						PackageName:  "bash",
						Epoch:        0,
						OSName:       "Fedora Linux",
						SourceRPM:    "bash-4.4-150400.25.22.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-3.0-or-later",
					},
				},
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "bash-sh",
					Version:   "4.4-150400.25.22",
					Metadata: &rpm.Metadata{
						PackageName:  "bash-sh",
						Epoch:        0,
						SourceRPM:    "bash-4.4-150400.25.22.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-3.0-or-later",
					},
				},
			},
			wantResults: 137,
		},
		{
			name: "CentOS 7.9.2009 Packages file (Berkley DB)",
			// docker run --rm --entrypoint cat centos:centos7.9.2009 /var/lib/rpm/Packages > third_party/scalibr/extractor/filesystem/os/rpm/testdata/Packages
			path:             "testdata/Packages",
			osrelease:        fedora38,
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages"},
					Name:      "acl",
					Version:   "2.2.51-15.el7",
					Metadata: &rpm.Metadata{
						PackageName:  "acl",
						Epoch:        0,
						SourceRPM:    "acl-2.2.51-15.el7.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "x86_64",
						License:      "GPLv2+",
					},
				},
				{
					Locations: []string{"testdata/Packages"},
					Name:      "audit-libs",
					Version:   "2.8.5-4.el7",
					Metadata: &rpm.Metadata{
						PackageName:  "audit-libs",
						Epoch:        0,
						SourceRPM:    "audit-2.8.5-4.el7.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "x86_64",
						License:      "LGPLv2+",
					},
				},
				{
					Locations: []string{"testdata/Packages"},
					Name:      "basesystem",
					Version:   "10.0-7.el7.centos",
					Metadata: &rpm.Metadata{
						PackageName:  "basesystem",
						Epoch:        0,
						SourceRPM:    "basesystem-10.0-7.el7.centos.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "noarch",
						License:      "Public Domain",
					},
				},
			},
			wantResults: 148,
		},
		{
			name:             "file not found",
			path:             "testdata/foobar",
			wantInventory:    nil,
			wantResults:      0,
			wantErr:          os.ErrNotExist,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "empty",
			path:             "testdata/empty.sqlite",
			wantInventory:    nil,
			wantResults:      0,
			wantErr:          io.EOF,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid",
			wantInventory:    nil,
			wantResults:      0,
			wantErr:          io.ErrUnexpectedEOF,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "corrupt db times out",
			path:             "testdata/timeout/Packages",
			timeoutval:       1 * time.Second,
			wantInventory:    nil,
			wantResults:      0,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "RockyLinux 9.2.20230513 rpmdb.sqlite file (sqlite3)",
			// docker run --rm --entrypoint cat rockylinux:9.2.20230513 /var/lib/rpm/rpmdb.sqlite > third_party/scalibr/extractor/filesystem/os/rpm/testdata/rpmdb.sqlite
			path:             "testdata/rpmdb.sqlite",
			osrelease:        fedora38,
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "alternatives",
					Version:   "1.20-2.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "alternatives",
						Epoch:        0,
						SourceRPM:    "chkconfig-1.20-2.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "GPLv2",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "audit-libs",
					Version:   "3.0.7-103.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "audit-libs",
						Epoch:        0,
						SourceRPM:    "audit-3.0.7-103.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "LGPLv2+",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "basesystem",
					Version:   "11-13.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "basesystem",
						Epoch:        0,
						SourceRPM:    "basesystem-11-13.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "noarch",
						License:      "Public Domain",
					},
				},
			},
			wantResults: 141,
		},
		{
			name: "osrelease: no version_id",
			// docker run --rm --entrypoint cat rockylinux:9.2.20230513 /var/lib/rpm/rpmdb.sqlite > third_party/scalibr/extractor/filesystem/os/rpm/testdata/rpmdb.sqlite
			path: "testdata/rpmdb.sqlite",
			osrelease: `ID=fedora
			BUILD_ID=asdf`,
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "alternatives",
					Version:   "1.20-2.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "alternatives",
						Epoch:        0,
						SourceRPM:    "chkconfig-1.20-2.el9.src.rpm",
						OSID:         "fedora",
						OSBuildID:    "asdf",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "GPLv2",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "audit-libs",
					Version:   "3.0.7-103.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "audit-libs",
						Epoch:        0,
						SourceRPM:    "audit-3.0.7-103.el9.src.rpm",
						OSID:         "fedora",
						OSBuildID:    "asdf",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "LGPLv2+",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "basesystem",
					Version:   "11-13.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "basesystem",
						Epoch:        0,
						SourceRPM:    "basesystem-11-13.el9.src.rpm",
						OSID:         "fedora",
						OSBuildID:    "asdf",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "noarch",
						License:      "Public Domain",
					},
				},
			},
			wantResults: 141,
		},
		{
			name: "custom rpm",
			// https://www.redhat.com/sysadmin/create-rpm-package
			path: "testdata/Packages_epoch",
			osrelease: `NAME=Fedora
			VERSION="32 (Container Image)"
			ID=fedora
			VERSION_ID=32
			VERSION_CODENAME=""
			PLATFORM_ID="platform:f32"
			PRETTY_NAME="Fedora 32 (Container Image)"
			CPE_NAME="cpe:/o:fedoraproject:fedora:32"`,
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages"},
					Name:      "hello",
					Version:   "0.0.1-rls",
					Metadata: &rpm.Metadata{
						PackageName:  "hello",
						Epoch:        1,
						SourceRPM:    "hello-0.0.1-rls.src.rpm",
						OSID:         "fedora",
						OSName:       "Fedora",
						OSVersionID:  "32",
						Architecture: "x86_64",
						License:      "GPL",
					},
				},
			},
			wantResults: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			createOsRelease(t, d, tt.osrelease)

			// Copy files to a temp directory, as sqlite can't open them directly.
			tmpPath, err := CopyFileToTempDir(t, tt.path, d)
			if err != nil {
				t.Fatalf("CopyFileToTempDir(%s) error: %v\n", tt.path, err)
			}

			info, err := os.Stat(tmpPath)
			if err != nil && !os.IsNotExist(err) {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			collector := testcollector.New()
			var e filesystem.Extractor = rpm.New(rpm.Config{
				Stats:   collector,
				Timeout: tt.timeoutval,
			})

			input := &filesystem.ScanInput{
				FS:   scalibrfs.DirFS(filepath.Dir(tmpPath)),
				Path: filepath.Base(tmpPath),
				Root: filepath.Dir(tmpPath),
				Info: info,
			}
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tmpPath, err, tt.wantErr)
			}

			// Update location with the temp path.
			for _, i := range tt.wantInventory {
				i.Locations = []string{filepath.Base(tmpPath)}
			}

			sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
			gotFirst3 := got[:min(len(got), 3)]
			if diff := cmp.Diff(tt.wantInventory, gotFirst3); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tmpPath, diff)
			}

			if len(got) != tt.wantResults {
				t.Errorf("Extract(%s): got %d results, want %d\n", tmpPath, len(got), tt.wantResults)
			}

			gotResultMetric := collector.FileExtractedResult(filepath.Base(tmpPath))
			if tt.wantResultMetric != "" && gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tmpPath, gotResultMetric, tt.wantResultMetric)
			}

			var wantFileSize int64
			if info != nil {
				wantFileSize = info.Size()
			}
			gotFileSizeMetric := collector.FileExtractedFileSize(filepath.Base(tmpPath))
			if gotFileSizeMetric != wantFileSize {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tmpPath, gotFileSizeMetric, wantFileSize)
			}
		})
	}
}

func TestExtract_VirtualFilesystem(t *testing.T) {
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name       string
		path       string
		osrelease  string
		timeoutval time.Duration
		// rpm -qa --qf "%{NAME}@%{VERSION}-%{RELEASE}\n" |sort |head -n 3
		wantInventory []*extractor.Inventory
		// rpm -qa | wc -l
		wantResults int
		wantErr     error
	}{
		{
			name: "opensuse/leap:15.5 Packages.db file (NDB)",
			// docker run --rm --entrypoint cat opensuse/leap:15.5 /var/lib/rpm/Packages.db > third_party/scalibr/extractor/filesystem/os/rpm/testdata/Packages.db
			path:      "testdata/Packages.db",
			osrelease: fedora38,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "aaa_base",
					Version:   "84.87+git20180409.04c9dae-150300.10.3.1",
					Metadata: &rpm.Metadata{
						PackageName:  "aaa_base",
						Epoch:        0,
						SourceRPM:    "aaa_base-84.87+git20180409.04c9dae-150300.10.3.1.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-2.0+",
					},
				},
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "bash",
					Version:   "4.4-150400.25.22",
					Metadata: &rpm.Metadata{
						PackageName:  "bash",
						Epoch:        0,
						OSName:       "Fedora Linux",
						SourceRPM:    "bash-4.4-150400.25.22.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-3.0-or-later",
					},
				},
				{
					Locations: []string{"testdata/Packages.db"},
					Name:      "bash-sh",
					Version:   "4.4-150400.25.22",
					Metadata: &rpm.Metadata{
						PackageName:  "bash-sh",
						Epoch:        0,
						SourceRPM:    "bash-4.4-150400.25.22.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "SUSE LLC <https://www.suse.com/>",
						Architecture: "x86_64",
						License:      "GPL-3.0-or-later",
					},
				},
			},
			wantResults: 137,
		},
		{
			name: "CentOS 7.9.2009 Packages file (Berkley DB)",
			// docker run --rm --entrypoint cat centos:centos7.9.2009 /var/lib/rpm/Packages > third_party/scalibr/extractor/filesystem/os/rpm/testdata/Packages
			path:      "testdata/Packages",
			osrelease: fedora38,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages"},
					Name:      "acl",
					Version:   "2.2.51-15.el7",
					Metadata: &rpm.Metadata{
						PackageName:  "acl",
						Epoch:        0,
						SourceRPM:    "acl-2.2.51-15.el7.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "x86_64",
						License:      "GPLv2+",
					},
				},
				{
					Locations: []string{"testdata/Packages"},
					Name:      "audit-libs",
					Version:   "2.8.5-4.el7",
					Metadata: &rpm.Metadata{
						PackageName:  "audit-libs",
						Epoch:        0,
						SourceRPM:    "audit-2.8.5-4.el7.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "x86_64",
						License:      "LGPLv2+",
					},
				},
				{
					Locations: []string{"testdata/Packages"},
					Name:      "basesystem",
					Version:   "10.0-7.el7.centos",
					Metadata: &rpm.Metadata{
						PackageName:  "basesystem",
						Epoch:        0,
						SourceRPM:    "basesystem-10.0-7.el7.centos.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "CentOS",
						Architecture: "noarch",
						License:      "Public Domain",
					},
				},
			},
			wantResults: 148,
		},
		{
			name: "RockyLinux 9.2.20230513 rpmdb.sqlite file (sqlite3)",
			// docker run --rm --entrypoint cat rockylinux:9.2.20230513 /var/lib/rpm/rpmdb.sqlite > third_party/scalibr/extractor/filesystem/os/rpm/testdata/rpmdb.sqlite
			path:      "testdata/rpmdb.sqlite",
			osrelease: fedora38,
			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "alternatives",
					Version:   "1.20-2.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "alternatives",
						Epoch:        0,
						SourceRPM:    "chkconfig-1.20-2.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "GPLv2",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "audit-libs",
					Version:   "3.0.7-103.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "audit-libs",
						Epoch:        0,
						SourceRPM:    "audit-3.0.7-103.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "x86_64",
						License:      "LGPLv2+",
					},
				},
				{
					Locations: []string{"testdata/rpmdb.sqlite"},
					Name:      "basesystem",
					Version:   "11-13.el9",
					Metadata: &rpm.Metadata{
						PackageName:  "basesystem",
						Epoch:        0,
						SourceRPM:    "basesystem-11-13.el9.src.rpm",
						OSID:         "fedora",
						OSVersionID:  "38",
						OSName:       "Fedora Linux",
						Vendor:       "Rocky Enterprise Software Foundation",
						Architecture: "noarch",
						License:      "Public Domain",
					},
				},
			},
			wantResults: 141,
		},
		{
			name: "custom rpm",
			// https://www.redhat.com/sysadmin/create-rpm-package
			path: "testdata/Packages_epoch",
			osrelease: `NAME=Fedora
			VERSION="32 (Container Image)"
			ID=fedora
			VERSION_ID=32
			VERSION_CODENAME=""
			PLATFORM_ID="platform:f32"
			PRETTY_NAME="Fedora 32 (Container Image)"
			CPE_NAME="cpe:/o:fedoraproject:fedora:32"`,

			wantInventory: []*extractor.Inventory{
				{
					Locations: []string{"testdata/Packages_epoch"},
					Name:      "hello",
					Version:   "0.0.1-rls",
					Metadata: &rpm.Metadata{
						PackageName:  "hello",
						Epoch:        1,
						SourceRPM:    "hello-0.0.1-rls.src.rpm",
						OSID:         "fedora",
						OSName:       "Fedora",
						OSVersionID:  "32",
						Architecture: "x86_64",
						License:      "GPL",
					},
				},
			},
			wantResults: 1,
		},
		{
			name:          "empty",
			path:          "testdata/empty.sqlite",
			wantInventory: nil,
			wantResults:   0,
			wantErr:       io.EOF,
		},
		{
			name:          "invalid",
			path:          "testdata/invalid",
			wantInventory: nil,
			wantResults:   0,
			wantErr:       io.ErrUnexpectedEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
				FS: scalibrfs.DirFS(d), Path: tt.path, Reader: r, Info: info,
			}

			got, err := rpm.New(rpm.Config{}).Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}

			sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
			gotFirst3 := got[:min(len(got), 3)]
			if diff := cmp.Diff(tt.wantInventory, gotFirst3); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			if len(got) != tt.wantResults {
				t.Errorf("Extract(%s): got %d results, want %d\n", tt.path, len(got), tt.wantResults)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	pkgname := "pkgname"
	source := "source.rpm"
	version := "1.2.3"
	epoch := 1
	e := rpm.Extractor{}
	tests := []struct {
		name     string
		metadata *rpm.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "version ID and build ID present",
			metadata: &rpm.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSID:        "fedora",
				OSVersionID: "32",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "fedora",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "fedora-32",
					purl.SourceRPM: source,
				}),
			},
		},
		{
			name: "only build ID present",
			metadata: &rpm.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSID:        "fedora",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "fedora",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "fedora-asdf",
					purl.SourceRPM: source,
				}),
			},
		},
		{
			name: "ID missing",
			metadata: &rpm.Metadata{
				PackageName: pkgname,
				SourceRPM:   source,
				Epoch:       epoch,
				OSVersionID: "32",
				OSBuildID:   "asdf",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeRPM,
				Name:      pkgname,
				Namespace: "",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Epoch:     "1",
					purl.Distro:    "32",
					purl.SourceRPM: source,
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
	// supported OSes
	if !slices.Contains([]string{"linux"}, runtime.GOOS) {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}
	e := rpm.Extractor{}
	tests := []struct {
		name     string
		metadata *rpm.Metadata
		want     string
	}{
		{
			name: "RHEL",
			metadata: &rpm.Metadata{
				OSID: "rhel",
			},
			want: "Red Hat",
		},
		{
			name: "rocky",
			metadata: &rpm.Metadata{
				OSID: "rocky",
			},
			want: "Rocky Linux",
		},
		{
			name:     "OS ID not present",
			metadata: &rpm.Metadata{},
			want:     "",
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

// CopyFileToTempDir copies the passed in file to a temporary directory, then returns the new file path.
func CopyFileToTempDir(t *testing.T, filepath, root string) (string, error) {
	t.Helper()

	filename := path.Base(filepath)
	newfile := path.Join(root, filename)

	bytes, err := os.ReadFile(filepath)
	if os.IsNotExist(err) {
		return newfile, nil
	}
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(newfile, bytes, 0400); err != nil {
		return "", err
	}
	return newfile, nil
}

func createOsRelease(t *testing.T, root string, content string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "etc"), 0755)
	err := os.WriteFile(filepath.Join(root, "etc/os-release"), []byte(content), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "etc/os-release"), err)
	}
}
