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

package gemspec_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
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
			name:             "yaml gemspec",
			path:             "testdata/yaml-0.2.1.gemspec",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "ruby file",
			path:         "testdata/test.rb",
			wantRequired: false,
		},
		{
			name:             "yaml gemspec required if file size < max file size",
			path:             "testdata/yaml-0.2.1.gemspec",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "yaml gemspec required if file size == max file size",
			path:             "testdata/yaml-0.2.1.gemspec",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "yaml gemspec not required if file size > max file size",
			path:             "testdata/yaml-0.2.1.gemspec",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "yaml gemspec required if max file size set to 0",
			path:             "testdata/yaml-0.2.1.gemspec",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := gemspec.New(&cpb.PluginConfig{MaxFileSizeBytes: test.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("gemspec.New(%v) error: %v", test.maxFileSizeBytes, err)
			}
			e.(*gemspec.Extractor).Stats = collector

			// Set default size if not provided.
			fileSizeBytes := test.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 100 * units.KiB
			}

			isRequired := e.FileRequired(simplefileapi.New(test.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(test.path),
				FileMode: fs.ModePerm,
				FileSize: fileSizeBytes,
			}))
			if isRequired != test.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", test.path, isRequired, test.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(test.path)
			if gotResultMetric != test.wantResultMetric {
				t.Errorf("FileRequired(%s) recorded result metric %v, want result metric %v", test.path, gotResultMetric, test.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "yaml_gemspec",
			path: "testdata/yaml-0.2.1.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "yaml",
					Version:   "0.2.1",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/yaml-0.2.1.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "rss_gemspec",
			path: "testdata/rss-0.2.9.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "rss",
					Version:   "0.2.9",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/rss-0.2.9.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant gemspec",
			path: "testdata/version_constant/version_constant.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app",
					Version:   "1.2.3",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant/version_constant.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant with freeze",
			path: "testdata/version_constant_freeze/version_constant_freeze.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_freeze",
					Version:   "2.3.4",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_freeze/version_constant_freeze.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version inline constant",
			path: "testdata/version_inline.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_inline",
					Version:   "3.0.0",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_inline.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via File.join",
			path: "testdata/version_constant_join/version_constant_join.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_join",
					Version:   "4.5.6",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_join/version_constant_join.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via File.join multiline",
			path: "testdata/version_constant_join_multiline/version_constant_join_multiline.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_join_multiline",
					Version:   "7.8.9",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_join_multiline/version_constant_join_multiline.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via File.expand_path",
			path: "testdata/version_constant_expand/version_constant_expand.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_expand",
					Version:   "5.6.7",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_expand/version_constant_expand.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via File.dirname",
			path: "testdata/version_constant_dirname/version_constant_dirname.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_dirname",
					Version:   "8.9.0",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_dirname/version_constant_dirname.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via require",
			path: "testdata/version_constant_require/version_constant_require.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_require",
					Version:   "0.9.9",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_require/version_constant_require.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via conditional require",
			path: "testdata/version_constant_conditional/version_constant_conditional.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_conditional",
					Version:   "9.0.1",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_conditional/version_constant_conditional.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant via nested File.expand_path and File.join",
			path: "testdata/version_constant_expand_join/version_constant_expand_join.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app_expand_join",
					Version:   "6.7.8",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_expand_join/version_constant_expand_join.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid gemspec",
			path:             "testdata/invalid.gemspec",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "version constant missing definition",
			path:             "testdata/version_constant_missing/version_constant_missing.gemspec",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "empty gemspec",
			path:             "testdata/empty.gemspec",
			wantPackages:     nil,
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "bad definition gemspec",
			path:             "testdata/badspec.gemspec",
			wantPackages:     nil,
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant class",
			path: "testdata/version_constant_class/version_constant_class.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app",
					Version:   "3.0.0",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_class/version_constant_class.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "version constant different casing",
			path: "testdata/version_constant_different_casing/version_constant_different_casing.gemspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "example_app",
					Version:   "4.0.0",
					PURLType:  purl.TypeGem,
					Locations: []string{"testdata/version_constant_different_casing/version_constant_different_casing.gemspec"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "version method not supported",
			path:             "testdata/version_method/version_method.gemspec",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
		{
			name:             "load path not supported",
			path:             "testdata/version_load_path/version_load_path.gemspec",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := gemspec.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("gemspec.New() error: %v", err)
			}
			e.(*gemspec.Extractor).Stats = collector

			r, err := os.Open(test.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(test.path)
			if err != nil {
				t.Fatalf("Failed to stat test file: %v", err)
			}

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: test.path, Reader: r, Info: info}
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", test.name, err, test.wantErr)
			}

			var want inventory.Inventory
			if test.wantPackages != nil {
				want = inventory.Inventory{Packages: test.wantPackages}
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%+v) diff (-want +got):\n%s", test.name, diff)
			}

			gotResultMetric := collector.FileExtractedResult(test.path)
			if gotResultMetric != test.wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", test.path, gotResultMetric, test.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(test.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", test.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
