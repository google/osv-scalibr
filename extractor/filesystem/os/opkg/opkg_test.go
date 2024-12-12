// Copyright 2024 Google LLC
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

package opkg_test

import (
	"context"
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
	"github.com/google/osv-scalibr/extractor/filesystem/os/opkg"
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
		cfg     opkg.Config
		wantCfg opkg.Config
	}{
		{
			name: "default",
			cfg:  opkg.DefaultConfig(),
			wantCfg: opkg.Config{
				MaxFileSizeBytes:    10 * units.MiB,
				IncludeNotInstalled: false,
			},
		},
		{
			name: "custom",
			cfg: opkg.Config{
				MaxFileSizeBytes:    10,
				IncludeNotInstalled: true,
			},
			wantCfg: opkg.Config{
				MaxFileSizeBytes:    10,
				IncludeNotInstalled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := opkg.New(tt.cfg)
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
			path:             "usr/lib/opkg/status",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "status as a directory",
			path:         "usr/lib/opkg/status/foo",
			wantRequired: false,
		},
		{
			name:             "status file required if file size < max file size",
			path:             "usr/lib/opkg/status",
			fileSizeBytes:    10 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "status file required if file size == max file size",
			path:             "usr/lib/opkg/status",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "status file not required if file size > max file size",
			path:             "usr/lib/opkg/status",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "status file required if max file size set to 0",
			path:             "usr/lib/opkg/status",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = opkg.New(opkg.Config{
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
		cfg              opkg.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
		wantLogWarn      int
		wantLogErr       int
	}{
		{
			name:      "valid opkg status file",
			path:      "testdata/valid", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,      // You can mock the os-release data as needed
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/valid"},
				},
				{
					Name:    "libuci20130104",
					Version: "2023.08.10~5781664d-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "libuci20130104",
						PackageVersion:    "2023.08.10~5781664d-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/valid"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &opkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "packages with no version set are skipped",
			path:      "testdata/noversion",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/noversion"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &opkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/noversion"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "packages with no name set are skipped",
			path:      "testdata/nopackage",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/nopackage"},
				},
				{
					Name:    "busybox",
					Version: "1.36.1-r2",
					Metadata: &opkg.Metadata{
						PackageName:       "busybox",
						PackageVersion:    "1.36.1-r2",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/nopackage"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      1,
		},
		{
			name:      "statusfield",
			path:      "testdata/statusfield", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,            // You can mock the os-release data as needed
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "statusfield including not installed",
			path:      "testdata/statusfield", // Path to your OPKG status file in the test data
			osrelease: OpkgRelease,            // You can mock the os-release data as needed
			cfg: opkg.Config{
				IncludeNotInstalled: true,
			},
			wantInventory: []*extractor.Inventory{
				{
					Name:    "wantinstall_installed",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantinstall_installed",
						PackageVersion:    "1.0",
						Status:            "install ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
				{
					Name:    "wantdeinstall_configfiles",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantdeinstall_configfiles",
						PackageVersion:    "1.0",
						Status:            "deinstall ok config-files",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
				{
					Name:    "wantinstall_unpacked",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantinstall_unpacked",
						PackageVersion:    "1.0",
						Status:            "install ok unpacked",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
				{
					Name:    "wantpurge_installed",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantpurge_installed",
						PackageVersion:    "1.0",
						Status:            "purge ok installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
				{
					Name:    "wantpurge_notinstalled",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantpurge_notinstalled",
						PackageVersion:    "1.0",
						Status:            "purge ok not-installed",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
				{
					Name:    "wantnostatus",
					Version: "1.0",
					Metadata: &opkg.Metadata{
						PackageName:       "wantnostatus",
						PackageVersion:    "1.0",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/statusfield"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/empty",
			osrelease:        OpkgRelease,
			wantInventory:    []*extractor.Inventory{},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid",
			osrelease:        OpkgRelease,
			wantInventory:    []*extractor.Inventory{},
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name: "VERSION_CODENAME not set, fallback to VERSION_ID",
			path: "testdata/single",
			osrelease: `VERSION_ID="21.02.1"
			ID=openwrt`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:    "ubus",
						PackageVersion: "2024.10.20~252a9b0c-r1",
						Status:         "install ok installed",
						Architecture:   "x86_64",
						OSID:           "openwrt",
						OSVersionID:    "21.02.1",
					},
					Locations: []string{"testdata/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "no version",
			path:      "testdata/single",
			osrelease: `ID=openwrt`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:    "ubus",
						PackageVersion: "2024.10.20~252a9b0c-r1",
						Status:         "install ok installed",
						Architecture:   "x86_64",
						OSID:           "openwrt",
					},
					Locations: []string{"testdata/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "osrelease id not set",
			path:      "testdata/single",
			osrelease: `VERSION_CODENAME=openwrt-21.02.1`,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSVersionCodename: "openwrt-21.02.1",
					},
					Locations: []string{"testdata/single"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:      "newlines",
			path:      "testdata/trailingnewlines",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations: []string{"testdata/trailingnewlines"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
			wantLogWarn:      0,
			wantLogErr:       0,
		},
		{
			name:      "transitional packages should be annotated",
			path:      "testdata/transitional",
			osrelease: OpkgRelease,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "ubus",
					Version: "2024.10.20~252a9b0c-r1",
					Metadata: &opkg.Metadata{
						PackageName:       "ubus",
						PackageVersion:    "2024.10.20~252a9b0c-r1",
						Status:            "install ok installed",
						Architecture:      "x86_64",
						OSID:              "openwrt",
						OSVersionCodename: "openwrt-21.02.1",
						OSVersionID:       "21.02.1",
					},
					Locations:   []string{"testdata/transitional"},
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

			e := opkg.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(context.Background(), input)
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
	path := "testdata/single"
	want := []*extractor.Inventory{
		{
			Name:    "ubus",
			Version: "2024.10.20~252a9b0c-r1",
			Metadata: &opkg.Metadata{
				PackageName:    "ubus",
				PackageVersion: "2024.10.20~252a9b0c-r1",
				Status:         "install ok installed",
				Architecture:   "x86_64",
				OSID:           "",
				OSVersionID:    "",
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

	e := opkg.New(opkg.DefaultConfig())
	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract(%s) error: %v", path, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Extract(%s) (-want +got):\n%s", path, diff)
	}
}

func TestToPURL(t *testing.T) {
	pkgname := "pkgname"
	version := "1.2.3"
	e := opkg.Extractor{}
	tests := []struct {
		name     string
		metadata *opkg.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "OS ID and OS Version set (OpenWrt)",
			metadata: &opkg.Metadata{
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
			name: "OS ID not set, fallback to linux",
			metadata: &opkg.Metadata{
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
	e := opkg.Extractor{}
	tests := []struct {
		name     string
		metadata *opkg.Metadata
		want     string
	}{
		{
			name: "OS ID present (OpenWrt)",
			metadata: &opkg.Metadata{
				OSID: "openwrt",
			},
			want: "Openwrt",
		},
		{
			name:     "OS ID not present",
			metadata: &opkg.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present (OpenWrt)",
			metadata: &opkg.Metadata{
				OSID:        "openwrt",
				OSVersionID: "22.03.5",
			},
			want: "Openwrt:22.03.5",
		},
		{
			name: "OS version present (Generic Linux)",
			metadata: &opkg.Metadata{
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
func defaultConfigWith(cfg opkg.Config) opkg.Config {
	newCfg := opkg.DefaultConfig()

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
