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

package portage_test

import (
	"context"
	"io/fs"
	golog "log"
	"os"
	"path/filepath"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     portage.Config
		wantCfg portage.Config
	}{
		{
			name: "default",
			cfg:  portage.DefaultConfig(),
			wantCfg: portage.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: portage.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: portage.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := portage.New(tt.cfg)
			if diff := cmp.Diff(tt.wantCfg, got.Config()); diff != "" {
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
			name:             "PF file",
			path:             "var/db/pkg/perl-core/Getopt-Long-2.580.0/PF",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "file not required",
			path:         "var/db/pkg/perl-core/Getopt-Long-2.580.0/FAKE",
			wantRequired: false,
		},
		{
			name:             "PF file required if file size < max file size",
			path:             "var/db/pkg/perl-core/Getopt-Long-2.580.0/PF",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "PF file required if file size == max file size",
			path:             "var/db/pkg/perl-core/Getopt-Long-2.580.0/PF",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "PF file not required if file size > max file size",
			path:             "var/db/pkg/perl-core/Getopt-Long-2.580.0/PF",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "PF file required if max file size set to 0",
			path:             "var/db/pkg/perl-core/Getopt-Long-2.580.0/PF",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = portage.New(portage.Config{
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

const Gentoo = `NAME=Gentoo
ID=gentoo
PRETTY_NAME="Gentoo Linux"
ANSI_COLOR="1;32"
HOME_URL="https://www.gentoo.org/"
SUPPORT_URL="https://www.gentoo.org/support/"
BUG_REPORT_URL="https://bugs.gentoo.org/"
VERSION_ID="2.17"`

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		osrelease        string
		cfg              portage.Config
		wantInventory    []*extractor.Inventory
		wantErr          int
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid PF file",
			path:      "testdata/valid",
			osrelease: Gentoo,
			wantInventory: []*extractor.Inventory{
				{
					Name:    "Getopt-Long",
					Version: "2.580.0",
					Metadata: &portage.Metadata{
						PackageName:    "Getopt-Long",
						PackageVersion: "2.580.0",
						OSID:           "gentoo",
						OSVersionID:    "2.17",
					},
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "not valid PF file",
			path:             "testdata/invalid",
			osrelease:        Gentoo,
			wantInventory:    nil,
			wantErr:          0,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "no version PF file",
			path:             "testdata/noversion",
			osrelease:        Gentoo,
			wantInventory:    nil,
			wantErr:          0,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "no pkg name PF file",
			path:             "testdata/nopackage",
			osrelease:        Gentoo,
			wantInventory:    nil,
			wantErr:          0,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "empty PF file",
			path:             "testdata/empty",
			osrelease:        Gentoo,
			wantInventory:    nil,
			wantErr:          0,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &testLogger{}
			collector := testcollector.New()
			var e filesystem.Extractor = portage.New(portage.Config{
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

			got, err := e.Extract(context.Background(), input)

			if diff := cmp.Diff(tt.wantInventory, got); diff != "" {
				t.Errorf("Inventory mismatch (-want +got):\n%s", diff)
			}
			if logger.errors != tt.wantErr {
				t.Errorf("Extract(%s) recorded %d errors, want %d errors", tt.path, logger.errors, tt.wantErr)
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

func TestToPURL(t *testing.T) {
	pkgName := "pkgName"
	pkgVersion := "pkgVersion"

	e := portage.Extractor{}
	tests := []struct {
		name     string
		metadata *portage.Metadata
		want     *purl.PackageURL
	}{
		{
			name: "all fields present",
			metadata: &portage.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           "Gentoo",
				OSVersionID:    "20241201.0.284684",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "Gentoo",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "20241201.0.284684",
				}),
			},
		},
		{
			name: "only VERSION_ID set",
			metadata: &portage.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           "linux",
				OSVersionID:    "2.17",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "2.17",
				}),
			},
		},
		{
			name: "ID not set, fallback to linux",
			metadata: &portage.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSVersionID:    "jammy",
			},
			want: &purl.PackageURL{
				Type:      purl.TypePortage,
				Name:      pkgName,
				Namespace: "linux",
				Version:   pkgVersion,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
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
	e := portage.Extractor{}
	tests := []struct {
		name     string
		metadata *portage.Metadata
		want     string
	}{
		{
			name: "OS ID present",
			metadata: &portage.Metadata{
				OSID: "gentoo",
			},
			want: "Gentoo",
		},
		{
			name:     "OS ID not present",
			metadata: &portage.Metadata{},
			want:     "Linux",
		},
		{
			name: "OS version present",
			metadata: &portage.Metadata{
				OSID:        "gentoo",
				OSVersionID: "2.17",
			},
			want: "Gentoo:2.17",
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
