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

package packagejson_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
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
			name:             "package.json at root",
			path:             "package.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "top level package.json",
			path:             "testdata/package.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "tests library",
			path:             "testdata/deps/accepts/package.json",
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "not package.json",
			path:         "testdata/test.js",
			wantRequired: false,
		},
		{
			name:             "package.json required if size less than maxFileSizeBytes",
			path:             "package.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 2000 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package.json required if size equal to maxFileSizeBytes",
			path:             "package.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "package.json not required if size greater than maxFileSizeBytes",
			path:             "package.json",
			fileSizeBytes:    10000 * units.MiB,
			maxFileSizeBytes: 1000 * units.MiB,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             "package.json required if maxFileSizeBytes explicitly set to 0",
			path:             "package.json",
			fileSizeBytes:    1000 * units.MiB,
			maxFileSizeBytes: 0,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e := packagejson.New(packagejson.Config{
				Stats:            collector,
				MaxFileSizeBytes: tt.maxFileSizeBytes,
			})

			// Set a default file size if not specified.
			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1 * units.KiB
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
		cfg              packagejson.Config
		wantInventory    []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "top level package.json",
			path: "testdata/package.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "testdata",
					Version:   "10.46.8",
					Locations: []string{"testdata/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Author: &packagejson.Person{
							Name:  "Developer",
							Email: "dev@corp.com",
							URL:   "http://blog.dev.com",
						},
					},
				},
			},
		},
		{
			name: "accepts",
			path: "testdata/deps/accepts/package.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "accepts",
					Version:   "1.3.8",
					Locations: []string{"testdata/deps/accepts/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							{
								Name:  "Douglas Christopher Wilson",
								Email: "doug@somethingdoug.com",
							},
							{
								Name:  "Jonathan Ong",
								Email: "me@jongleberry.com",
								URL:   "http://jongleberry.com",
							},
						},
					},
				},
			},
		},
		{
			name: "no person name",
			path: "testdata/deps/no-person-name/package.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "accepts",
					Version:   "1.3.8",
					Locations: []string{"testdata/deps/no-person-name/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							{
								Name:  "Jonathan Ong",
								Email: "me@jongleberry.com",
								URL:   "http://jongleberry.com",
							},
						},
					},
				},
			},
		},
		{
			name: "nested acorn",
			path: "testdata/deps/with/deps/acorn/package.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "acorn",
					Version:   "1.2.2",
					Locations: []string{"testdata/deps/with/deps/acorn/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Maintainers: []*packagejson.Person{
							{
								Name:  "Marijn Haverbeke",
								Email: "marijnh@gmail.com",
							},
							{
								Name:  "Ingvar Stepanyan",
								Email: "me@rreverser.com",
							},
						},
					},
				},
			},
		},
		{
			name:          "empty name",
			path:          "testdata/deps/acorn/package.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "empty version",
			path:          "testdata/deps/acorn-globals/package.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "missing name and version",
			path:          "testdata/deps/window-size/package.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "VSCode extension",
			path:          "testdata/vscode-extension.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "VSCode extension with only required fields",
			path:          "testdata/vscode-extension-only-required.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "Unity package",
			path:          "testdata/unity-package.json",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name: "Undici package with nonstandard contributors parsed correctly",
			path: "testdata/undici-package.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "undici",
					Version: "5.28.3",
					Locations: []string{
						"testdata/undici-package.json",
					},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							{
								Name: "Daniele Belardi",
								URL:  "https://github.com/dnlup",
							},
							{
								Name: "Tomas Della Vedova",
								URL:  "https://github.com/delvedor",
							},
							{
								Name: "Invalid URL NoCrash",
							},
						},
					},
				},
			},
		},
		{
			name: "npm package with engine field set",
			path: "testdata/not-vscode.json",
			wantInventory: []*extractor.Inventory{
				{
					Name:      "jsonparse",
					Version:   "1.3.1",
					Locations: []string{"testdata/not-vscode.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Author: &packagejson.Person{
							Name:  "Tim Caswell",
							Email: "tim@creationix.com",
						},
					},
				},
			},
		},
		{
			name:             "invalid packagejson",
			path:             "testdata/invalid",
			wantErr:          cmpopts.AnyError,
			wantResultMetric: stats.FileExtractedResultErrorUnknown,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
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
				t.Fatal(err)
			}

			collector := testcollector.New()
			tt.cfg.Stats = collector

			input := &filesystem.ScanInput{
				FS:     scalibrfs.DirFS("."),
				Path:   tt.path,
				Reader: r,
				Info:   info,
			}
			e := packagejson.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			var want []*extractor.Inventory
			if tt.wantInventory != nil {
				want = tt.wantInventory
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			wantResultMetric := tt.wantResultMetric
			if wantResultMetric == "" && tt.wantErr == nil {
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

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg packagejson.Config) packagejson.Config {
	newCfg := packagejson.DefaultConfig()

	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}
	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
	return newCfg
}

func TestToPURL(t *testing.T) {
	e := packagejson.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeNPM,
		Name:    "name",
		Version: "1.2.3",
	}
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
