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

package projectassetsjson_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/projectassetsjson"
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
			name:             "some project's project.assets.json",
			path:             "project/project.assets.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "just project.assets.json",
			path:             "project.assets.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "non project.assets.json",
			path:         "project/some.csproj",
			wantRequired: false,
		},
		{
			name:             "project.assets.json required if file size < max file size",
			path:             "project/project.assets.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "project.assets.json required if file size == max file size",
			path:             "project/project.assets.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "project.assets.json not required if file size > max file size",
			path:             "project/project.assets.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "project.assets.json required if max file size set to 0",
			path:             "project/project.assets.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := projectassetsjson.New(&cpb.PluginConfig{MaxFileSizeBytes: test.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*projectassetsjson.Extractor).Stats = collector

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

func TestExtractor(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		wantPackages     []*extractor.Package
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid_project.assets.json",
			path: "testdata/valid/project.assets.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "Microsoft.Build.Tasks.Git",
					Version:  "1.0.0-beta2-19351-01",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 459),
				},
				{
					Name:     "Microsoft.NETCore.Platforms",
					Version:  "1.1.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 506),
				},
				{
					Name:     "Microsoft.NETCore.Targets",
					Version:  "1.1.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 521),
				},
				{
					Name:     "Microsoft.SourceLink.Common",
					Version:  "1.0.0-beta2-19351-01",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 535),
				},
				{
					Name:     "Microsoft.SourceLink.GitHub",
					Version:  "1.0.0-beta2-19351-01",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 569),
				},
				{
					Name:     "Microsoft.Win32.Primitives",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 615),
				},
				{
					Name:     "Microsoft.Win32.Registry",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 652),
				},
				{
					Name:     "NETStandard.Library",
					Version:  "2.0.3",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 681),
				},
				{
					Name:     "System.Collections",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 823),
				},
				{
					Name:     "System.Diagnostics.Debug",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 890),
				},
				{
					Name:     "System.Diagnostics.Process",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 957),
				},
				{
					Name:     "System.Globalization",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1013),
				},
				{
					Name:     "System.IO",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1080),
				},
				{
					Name:     "System.IO.FileSystem",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1160),
				},
				{
					Name:     "System.IO.FileSystem.Primitives",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1197),
				},
				{
					Name:     "System.Reflection",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1235),
				},
				{
					Name:     "System.Reflection.Primitives",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1315),
				},
				{
					Name:     "System.Resources.ResourceManager",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1371),
				},
				{
					Name:     "System.Runtime",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1427),
				},
				{
					Name:     "System.Runtime.Extensions",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1518),
				},
				{
					Name:     "System.Runtime.Handles",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1598),
				},
				{
					Name:     "System.Runtime.InteropServices",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1635),
				},
				{
					Name:     "System.Text.Encoding",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1727),
				},
				{
					Name:     "System.Text.Encoding.Extensions",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1794),
				},
				{
					Name:     "System.Threading",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1861),
				},
				{
					Name:     "System.Threading.Tasks",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1931),
				},
				{
					Name:     "System.Threading.Thread",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 1999),
				},
				{
					Name:     "System.Threading.ThreadPool",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 2038),
				},
				{
					Name:     "runtime.native.System",
					Version:  "4.3.0",
					PURLType: purl.TypeNuget,
					Location: extractor.LocationFromPathAndLine("testdata/valid/project.assets.json", 810),
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "non json input",
			path:             "testdata/invalid/invalid",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := projectassetsjson.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("New() unexpected error: %v", err)
			}
			e.(*projectassetsjson.Extractor).Stats = collector

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

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   test.path,
				Reader: r,
				Info:   info,
			}
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", test.name, err, test.wantErr)
			}

			sort := func(a, b *extractor.Package) bool { return a.Name < b.Name }
			wantInv := inventory.Inventory{Packages: test.wantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", test.path, diff)
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
