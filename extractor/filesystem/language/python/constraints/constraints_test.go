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

package constraints_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/constraints"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
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
			name:             "constraints.txt",
			path:             "project/constraints.txt",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "requirements.txt should not match",
			path:         "project/requirements.txt",
			wantRequired: false,
		},
		{
			name:         "other txt file should not match",
			path:         "project/other.txt",
			wantRequired: false,
		},
		{
			name:             "constraints.txt within size limit",
			path:             "project/constraints.txt",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "constraints.txt at exact size limit",
			path:             "project/constraints.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "constraints.txt exceeds size limit",
			path:             "project/constraints.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "constraints.txt required if max file size is 0",
			path:             "project/constraints.txt",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := constraints.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("constraints.New() error: %v", err)
			}
			e.(*constraints.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
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
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantPackages     []*extractor.Package
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid",
			path: "testdata/valid.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.28.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 1),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "==", Requirement: "requests==2.28.0"},
				},
				{
					Name:     "flask",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 2),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: ">=", Requirement: "flask>=2.0.0"},
				},
				{
					Name:     "numpy",
					Version:  "1.24.0,<2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 3),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: ">=", Requirement: "numpy>=1.24.0,<2.0.0"},
				},
				{
					Name:     "django",
					Version:  "3.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 4),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: ">", Requirement: "django>3.0"},
				},
				{
					Name:     "pillow",
					Version:  "10.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 5),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "<", Requirement: "pillow<10.0"},
				},
				{
					Name:     "pytest",
					Version:  "7.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 6),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "!=", Requirement: "pytest!=7.0.0"},
				},
				{
					Name:     "scipy",
					Version:  "1.9.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 7),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "~=", Requirement: "scipy~=1.9.0"},
				},
				{
					Name:     "a",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 8),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "==", Requirement: "a==1.0.0"},
				},
				{
					Name:     "zope.interface",
					Version:  "6.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.txt", 9),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "==", Requirement: "zope.interface==6.0"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/empty.txt",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "comments",
			path: "testdata/comments.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					Version:  "2.28.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.txt", 2),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: "==", Requirement: "requests==2.28.0"},
				},
				{
					Name:     "flask",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.txt", 4),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: ">=", Requirement: "flask>=2.0.0"},
				},
				{
					Name:     "numpy",
					Version:  "1.24.0,<2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.txt", 5),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, VersionComparator: ">=", Requirement: "numpy>=1.24.0,<2.0.0"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "no_version",
			path: "testdata/no_version.txt",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.txt", 1),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, Requirement: "requests"},
				},
				{
					Name:     "flask",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.txt", 2),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, Requirement: "flask"},
				},
				{
					Name:     "numpy",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.txt", 3),
					Metadata: &requirements.Metadata{HashCheckingModeValues: []string{}, Requirement: "numpy"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid.txt",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := constraints.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("constraints.New() error: %v", err)
			}
			e.(*constraints.Extractor).Stats = collector

			fsys := scalibrfs.DirFS(".")
			r, err := fsys.Open(tt.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()

			info, err := r.Stat()
			if err != nil {
				t.Fatalf("Stat(): %v", err)
			}

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}
			got, err := e.Extract(t.Context(), input)
			if err != nil {
				t.Fatalf("Extract(%s): %v", tt.path, err)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != tt.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
