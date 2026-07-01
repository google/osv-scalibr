// Copyright 2026 Google LLC
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

package deb_test

import (
	"fmt"
	"io/fs"
	golog "log"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/deb"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	scalibrlog "github.com/google/osv-scalibr/log"
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
			name:             "deb file",
			path:             "valid.deb",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "deb file required if file size < max file size",
			path:             "valid.deb",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "deb file required if file size == max file size",
			path:             "valid.deb",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "deb file not required if file size > max file size",
			path:             "valid.deb",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "deb file required if max file size set to 0",
			path:             "valid.deb",
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
			e, err := deb.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("deb.New: %v", err)
			}
			e.(*deb.Extractor).Stats = collector

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

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		cfg              *cpb.PluginConfig
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid deb file",
			path: "testdata/valid.deb",
			wantPackages: []*extractor.Package{
				{
					Name:     "bash",
					Version:  "5.2.37-2+b8",
					PURLType: purl.TypeDebian,
					Metadata: &dpkgmeta.Metadata{
						PackageName:    "bash",
						PackageVersion: "5.2.37-2+b8",
						SourceName:     "bash",
						SourceVersion:  "5.2.37-2",
						Maintainer:     "Matthias Klose <doko@debian.org>",
						Architecture:   "amd64",
					},
					Location: extractor.LocationFromPath("testdata/valid.deb"),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:         "packages with no version set are skipped",
			path:         "testdata/noversion.deb",
			wantPackages: nil,
			wantErr:      cmpopts.AnyError,
		},
		{
			name:         "packages with no name set are skipped",
			path:         "testdata/noname.deb",
			wantPackages: nil,
			wantErr:      cmpopts.AnyError,
		},
		{
			name:         "empty",
			path:         "testdata/empty.deb",
			wantPackages: nil,
			wantErr:      cmpopts.AnyError,
		},
		{
			name:         "invalid",
			path:         "testdata/invalid.deb",
			wantPackages: nil,
			wantErr:      cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			logger := &testLogger{}
			scalibrlog.SetLogger(logger)

			collector := testcollector.New()

			d := t.TempDir()

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
			e, err := deb.New(cfg)
			if err != nil {
				t.Fatalf("deb.New: %v", err)
			}
			e.(*deb.Extractor).Stats = collector
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

			if tt.wantResultMetric != "" {
				gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
				if gotFileSizeMetric != info.Size() {
					t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
				}
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
