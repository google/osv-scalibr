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

package requirementsin_test

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirementsin"
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
			name:             "requirements.in",
			path:             "project/requirements.in",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.in in root",
			path:             "requirements.in",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not requirements.in",
			path:         "project/requirements.txt",
			wantRequired: false,
		},
		{
			name:         "wrong extension",
			path:         "project/dev-requirements.in",
			wantRequired: false,
		},
		{
			name:             "requirements.in required if file size < max file size",
			path:             "project/requirements.in",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.in required if file size == max file size",
			path:             "project/requirements.in",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "requirements.in not required if file size > max file size",
			path:             "project/requirements.in",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "requirements.in required if max file size is 0",
			path:             "project/requirements.in",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := requirementsin.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("requirementsin.New(%v) error: %v", tt.maxFileSizeBytes, err)
			}
			e.(*requirementsin.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
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
			path: "testdata/valid.in",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.in", 1),
					Metadata: &requirements.Metadata{Requirement: "requests"},
				},
				{
					Name:     "flask",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.in", 2),
					Metadata: &requirements.Metadata{VersionComparator: ">=", Requirement: "flask>=2.0.0"},
				},
				{
					Name:     "numpy",
					Version:  "1.24.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.in", 3),
					Metadata: &requirements.Metadata{VersionComparator: "==", Requirement: "numpy==1.24.0"},
				},
				{
					Name:     "a",
					Version:  "1.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.in", 4),
					Metadata: &requirements.Metadata{VersionComparator: "==", Requirement: "a==1.0.0"},
				},
				{
					Name:     "zope.interface",
					Version:  "6.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/valid.in", 5),
					Metadata: &requirements.Metadata{VersionComparator: "==", Requirement: "zope.interface==6.0"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty",
			path:             "testdata/empty.in",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "comments",
			path: "testdata/comments.in",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.in", 2),
					Metadata: &requirements.Metadata{Requirement: "requests"},
				},
				{
					Name:     "flask",
					Version:  "2.0.0",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/comments.in", 4),
					Metadata: &requirements.Metadata{VersionComparator: ">=", Requirement: "flask>=2.0.0"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "no_version",
			path: "testdata/no_version.in",
			wantPackages: []*extractor.Package{
				{
					Name:     "requests",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.in", 1),
					Metadata: &requirements.Metadata{Requirement: "requests"},
				},
				{
					Name:     "flask",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.in", 2),
					Metadata: &requirements.Metadata{Requirement: "flask"},
				},
				{
					Name:     "numpy",
					PURLType: purl.TypePyPi,
					Location: extractor.LocationFromPathAndLine("testdata/no_version.in", 3),
					Metadata: &requirements.Metadata{Requirement: "numpy"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid",
			path:             "testdata/invalid.in",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
	}

	for _, t := range tests {
		for _, p := range t.wantPackages {
			if p.Location.Descriptor == nil {
				p.Location = extractor.LocationFromPath(t.path)
			}
			if p.Metadata == nil {
				p.Metadata = &requirements.Metadata{}
			}
			if p.Metadata.(*requirements.Metadata).HashCheckingModeValues == nil {
				p.Metadata.(*requirements.Metadata).HashCheckingModeValues = []string{}
			}
			if p.Version != "" && p.Metadata.(*requirements.Metadata).VersionComparator == "" {
				p.Metadata.(*requirements.Metadata).VersionComparator = "=="
			}
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := requirementsin.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("requirementsin.New() error: %v", err)
			}
			e.(*requirementsin.Extractor).Stats = collector

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
