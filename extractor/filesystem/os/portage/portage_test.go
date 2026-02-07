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

package portage_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	portagemeta "github.com/google/osv-scalibr/extractor/filesystem/os/portage/metadata"
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
			e, err := portage.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("portage.New: %v", err)
			}
			e.(*portage.Extractor).Stats = collector

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
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name:      "valid PF file",
			path:      "testdata/valid",
			osrelease: Gentoo,
			wantPackages: []*extractor.Package{
				{
					Name:     "Getopt-Long",
					Version:  "2.580.0",
					PURLType: purl.TypePortage,
					Metadata: &portagemeta.Metadata{
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
			wantPackages:     nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "no version PF file",
			path:             "testdata/noversion",
			osrelease:        Gentoo,
			wantPackages:     nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "no package name PF file",
			path:             "testdata/nopackage",
			osrelease:        Gentoo,
			wantPackages:     nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "empty PF file",
			path:             "testdata/empty",
			osrelease:        Gentoo,
			wantPackages:     nil,
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := portage.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
			if err != nil {
				t.Fatalf("portage.New: %v", err)
			}
			e.(*portage.Extractor).Stats = collector

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

			wantInv := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(wantInv, got); diff != "" {
				t.Errorf("Package mismatch (-want +got):\n%s", diff)
			}
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
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
