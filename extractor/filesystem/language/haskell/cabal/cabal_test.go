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

package cabal_test

import (
	"context"
	"io/fs"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     cabal.Config
		wantCfg cabal.Config
	}{
		{
			name: "default",
			cfg:  cabal.DefaultConfig(),
			wantCfg: cabal.Config{
				MaxFileSizeBytes: 100 * units.MiB,
			},
		},
		{
			name: "custom",
			cfg: cabal.Config{
				MaxFileSizeBytes: 10,
			},
			wantCfg: cabal.Config{
				MaxFileSizeBytes: 10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cabal.New(tt.cfg)
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
			name:             "cabal.project.freeze file",
			path:             "software-develop/cabal.project.freeze",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal.project.freeze file required if file size < max file size",
			path:             "software-develop/cabal.project.freeze",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal.project.freeze file required if file size == max file size",
			path:             "software-develop/cabal.project.freeze",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 1000 * units.KiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "cabal.project.freeze file not required if file size > max file size",
			path:             "software-develop/cabal.project.freeze",
			fileSizeBytes:    1000 * units.KiB,
			maxFileSizeBytes: 100 * units.KiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "cabal.project.freeze file required if max file size set to 0",
			path:             "software-develop/cabal.project.freeze",
			fileSizeBytes:    100 * units.KiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not required",
			path:         "software-develop/cabal.project.freeze/foo",
			wantRequired: false,
		},
		{
			name:         "not required",
			path:         "software-develop/foocabal.project.freeze",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			var e filesystem.Extractor = cabal.New(cabal.Config{
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

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		cfg              cabal.Config
		wantInventory    []*extractor.Inventory
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "valid stack.yaml.lock file",
			path: "testdata/valid",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "AC-Angle",
					Version:   "1.0",
					Locations: []string{"testdata/valid"},
				},
				{
					Name:      "ALUT",
					Version:   "2.4.0.3",
					Locations: []string{"testdata/valid"},
				},
				{
					Name:      "ANum",
					Version:   "0.2.0.2",
					Locations: []string{"testdata/valid"},
				},
				{
					Name:      "Agda",
					Version:   "2.6.4.3",
					Locations: []string{"testdata/valid"},
				},
				{
					Name:      "Allure",
					Version:   "0.11.0.0",
					Locations: []string{"testdata/valid"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name: "valid stack.yaml.lock file with package problems",
			path: "testdata/valid_2",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "AC-Angle",
					Version:   "1.0",
					Locations: []string{"testdata/valid_2"},
				},
				{
					Name:      "ANum",
					Version:   "0.2.0.2",
					Locations: []string{"testdata/valid_2"},
				},
				{
					Name:      "Agda",
					Version:   "2.6.4.3",
					Locations: []string{"testdata/valid_2"},
				},
				{
					Name:      "Allure",
					Version:   "0.11.0.0",
					Locations: []string{"testdata/valid_2"},
				},
			},
			wantResultMetric: stats.FileExtractedResultSuccess,
		},
		{
			name:          "invalid",
			path:          "testdata/invalid",
			wantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := scalibrfs.DirFS(".")

			r, err := fsys.Open(tt.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := r.Stat()
			if err != nil {
				t.Fatalf("Stat(): %v", err)
			}

			collector := testcollector.New()
			tt.cfg.Stats = collector

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}
			var e filesystem.Extractor = cabal.New(defaultConfigWith(tt.cfg))

			got, err := e.Extract(context.Background(), input)

			if diff := cmp.Diff(tt.wantInventory, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" {
				wantResultMetric = stats.FileExtractedResultSuccess
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if gotResultMetric != wantResultMetric {
				t.Errorf("Extract(%s) recorded result metric %v, want result metric %v", tt.path, gotResultMetric, wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := cabal.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeHaskell,
		Name:    "Name",
		Version: "1.2.3",
	}
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}

func defaultConfigWith(cfg cabal.Config) cabal.Config {
	newCfg := cabal.DefaultConfig()

	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}
	return newCfg
}
