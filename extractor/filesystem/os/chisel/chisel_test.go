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
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     chisel.Config
		wantCfg chisel.Config
	}{
		{
			name: "default",
			cfg:  chisel.DefaultConfig(),
			wantCfg: chisel.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: chisel.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: chisel.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chisel.New(tt.cfg)
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
			name:             "manifest json wall file",
			path:             "var/lib/chisel/manifest.wall",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = chisel.New(chisel.Config{
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
		cfg              chisel.Config
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
		wantLogWarn      int
		wantLogErr       int
	}{
		{
			name:      "valid manifest wall file",
			path:      "testdata/chisel/openssl.wall",
			osrelease: UbuntuNoble,
			wantPackages: []*extractor.Package{
				{
					Name:    "base-files",
					Version: "13ubuntu10.2",
					Metadata: &chisel.Metadata{
						PackageName:       "base-files",
						PackageVersion:    "13ubuntu10.2",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/chisel/openssl.wall"},
				},
				{
					Name:    "libc6",
					Version: "2.39-0ubuntu8.4",
					Metadata: &chisel.Metadata{
						PackageName:       "libc6",
						PackageVersion:    "2.39-0ubuntu8.4",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/chisel/openssl.wall"},
				},
				{
					Name:    "libssl3t64",
					Version: "3.0.13-0ubuntu3.5",
					Metadata: &chisel.Metadata{
						PackageName:       "libssl3t64",
						PackageVersion:    "3.0.13-0ubuntu3.5",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/chisel/openssl.wall"},
				},
				{
					Name:    "openssl",
					Version: "3.0.13-0ubuntu3.5",
					Metadata: &chisel.Metadata{
						PackageName:       "openssl",
						PackageVersion:    "3.0.13-0ubuntu3.5",
						OSID:              "ubuntu",
						OSVersionCodename: "noble",
						OSVersionID:       "24.04",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/chisel/openssl.wall"},
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
					Metadata: &chisel.Metadata{
						PackageName:    "base-files",
						PackageVersion: "13ubuntu10.2",
						OSID:           "ubuntu",
						OSVersionID:    "24.04",
						Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/chisel/single.wall"},
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
					Metadata: &chisel.Metadata{
						PackageName:    "base-files",
						PackageVersion: "13ubuntu10.2",
						OSID:           "ubuntu",
						Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:   "amd64",
					},
					Locations: []string{"testdata/chisel/single.wall"},
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
					Metadata: &chisel.Metadata{
						PackageName:       "base-files",
						PackageVersion:    "13ubuntu10.2",
						OSVersionCodename: "noble",
						Maintainer:        "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
						Architecture:      "amd64",
					},
					Locations: []string{"testdata/chisel/single.wall"},
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

			e := chisel.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(context.Background(), input)
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
	path := "testdata/chisel/single.wall"

	want := inventory.Inventory{Packages: []*extractor.Package{
		{
			Name:    "base-files",
			Version: "13ubuntu10.2",
			Metadata: &chisel.Metadata{
				PackageName:    "base-files",
				PackageVersion: "13ubuntu10.2",
				OSID:           "",
				OSVersionID:    "",
				Maintainer:     "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>",
				Architecture:   "amd64",
			},
			Locations: []string{path},
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

	e := chisel.New(chisel.DefaultConfig())
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
	e := chisel.Extractor{}
	tests := []struct {
		name     string
		location string
		metadata *chisel.Metadata
		want     *purl.PackageURL
	}{
		{
			name:     "both OS versions present",
			location: "var/lib/chisel/status",
			metadata: &chisel.Metadata{
				PackageName:       pkgname,
				OSID:              "ubuntu",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeChisel,
				Name:      pkgname,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
		{
			name:     "only VERSION_ID set",
			location: "var/lib/chisel/status",
			metadata: &chisel.Metadata{
				PackageName: pkgname,
				OSID:        "ubuntu",
				OSVersionID: "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeChisel,
				Name:      pkgname,
				Namespace: "ubuntu",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.04",
				}),
			},
		},
		{
			name:     "ID not set, fallback to linux",
			location: "var/lib/chisel/status",
			metadata: &chisel.Metadata{
				PackageName:       pkgname,
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeChisel,
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
			p := &extractor.Package{
				Name:      pkgname,
				Version:   version,
				Metadata:  tt.metadata,
				Locations: []string{tt.location},
			}
			got := e.ToPURL(p)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ToPURL(%v) (-want +got):\n%s", p, diff)
			}
		})
	}
}

func TestEcosystem(t *testing.T) {
	e := chisel.Extractor{}
	tests := []struct {
		name     string
		metadata *chisel.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &chisel.Metadata{
				OSID: "ubuntu",
			},
			want: "Ubuntu",
		},
		{
			name:     "OS ID not present",
			metadata: &chisel.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &chisel.Metadata{
				OSID:        "ubuntu",
				OSVersionID: "24.04",
			},
			want: "Ubuntu:24.04",
		},
		{
			name: "OS version present (Generic Linux)",
			metadata: &chisel.Metadata{
				OSID:        "linux",
				OSVersionID: "5",
			},
			want: "Linux:5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &extractor.Package{
				Metadata: tt.metadata,
			}
			got := e.Ecosystem(p)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Ecosystem(%v) (-want +got):\n%s", p, diff)
			}
		})
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

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg chisel.Config) chisel.Config {
	newCfg := chisel.DefaultConfig()

	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}

	return newCfg
}
