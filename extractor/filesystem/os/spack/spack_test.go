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

package spack_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/spack"
	spackmeta "github.com/google/osv-scalibr/extractor/filesystem/os/spack/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
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
			name:             "spec.json file required if in .spack dir",
			path:             "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/spec.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "spec.json file required if file size < max file size",
			path:             "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/spec.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "spec.json file required if file size == max file size",
			path:             "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/spec.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "spec.json file not required if file size > max file size",
			path:             "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/spec.json",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "spec.json file required if max file size = 0",
			path:             "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/spec.json",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "json file not required if not in .spack dir",
			path:         "opt/spack/some-dir/spec.json",
			wantRequired: false,
		},
		{
			name:         "non-spec.json file in .spack dir not required",
			path:         "opt/spack/linux-ubuntu22.04-x86_64/gcc-11.4.0/libelf-0.8.13-abc123/.spack/other.json",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := spack.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("spack.New: %v", err)
			}
			e.(*spack.Extractor).Stats = collector

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
			name: "valid spec.json extracts non-external packages with metadata",
			path: "testdata/validspec.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "libelf",
					Version:  "0.8.13",
					PURLType: purl.TypeSpack,
					Metadata: &spackmeta.Metadata{
						PackageName:    "libelf",
						PackageVersion: "0.8.13",
						Hash:           "dsohcyk45wchbd364rjio7b3sj2bucgc",
						Platform:       "linux",
						PlatformOS:     "ubuntu24.04",
						Architecture:   "skylake",
					},
					Locations: []string{"testdata/validspec.json"},
				},
				{
					Name:     "compiler-wrapper",
					Version:  "1.0",
					PURLType: purl.TypeSpack,
					Metadata: &spackmeta.Metadata{
						PackageName:    "compiler-wrapper",
						PackageVersion: "1.0",
						Hash:           "i54t7tjn3prjyb363kdjgrkiawikdvyu",
						Platform:       "linux",
						PlatformOS:     "ubuntu24.04",
						Architecture:   "skylake",
					},
					Locations: []string{"testdata/validspec.json"},
				},
				{
					Name:     "gcc-runtime",
					Version:  "13.3.0",
					PURLType: purl.TypeSpack,
					Metadata: &spackmeta.Metadata{
						PackageName:    "gcc-runtime",
						PackageVersion: "13.3.0",
						Hash:           "l4tb2r6hhvx2fjqiecaesuf3pdusajjw",
						Platform:       "linux",
						PlatformOS:     "ubuntu24.04",
						Architecture:   "skylake",
					},
					Locations: []string{"testdata/validspec.json"},
				},
				{
					Name:     "gmake",
					Version:  "4.4.1",
					PURLType: purl.TypeSpack,
					Metadata: &spackmeta.Metadata{
						PackageName:    "gmake",
						PackageVersion: "4.4.1",
						Hash:           "e2bq6relcp3zp3cg7zq4ced6obys5bts",
						Platform:       "linux",
						PlatformOS:     "ubuntu24.04",
						Architecture:   "skylake",
					},
					Locations: []string{"testdata/validspec.json"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "empty nodes returns no packages",
			path:             "testdata/emptynodesspec.json",
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:             "invalid json returns error",
			path:             "testdata/invalidspec.json",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()

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

			input := &filesystem.ScanInput{Path: tt.path, Reader: r, Info: info}

			cfg := tt.cfg
			if cfg == nil {
				cfg = &cpb.PluginConfig{}
			}
			e, err := spack.New(cfg)
			if err != nil {
				t.Fatalf("spack.New: %v", err)
			}
			e.(*spack.Extractor).Stats = collector
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

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}
