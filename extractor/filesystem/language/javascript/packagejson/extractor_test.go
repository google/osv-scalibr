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

package packagejson_test

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = packagejson.New(packagejson.DefaultConfig())

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "package.json at root",
			path:           "package.json",
			wantIsRequired: true,
		},
		{
			name:           "top level package.json",
			path:           "testdata/package.json",
			wantIsRequired: true,
		},
		{
			name:           "tests library",
			path:           "testdata/deps/accepts/package.json",
			wantIsRequired: true,
		},
		{
			name:           "not package.json",
			path:           "testdata/test.js",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
		t.Run(tt.name, func(t *testing.T) {
			isRequired := e.FileRequired(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
			})
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		cfg           packagejson.Config
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name: "top level package.json",
			path: "testdata/package.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
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
			name: "file size over limit",
			path: "testdata/package.json",
			cfg: packagejson.Config{
				MaxJSONSize: 5,
			},
			wantErr: cmpopts.AnyError,
		},
		{
			name: "accepts",
			path: "testdata/deps/accepts/package.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "accepts",
					Version:   "1.3.8",
					Locations: []string{"testdata/deps/accepts/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							&packagejson.Person{
								Name:  "Douglas Christopher Wilson",
								Email: "doug@somethingdoug.com",
							},
							&packagejson.Person{
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
				&extractor.Inventory{
					Name:      "accepts",
					Version:   "1.3.8",
					Locations: []string{"testdata/deps/no-person-name/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							&packagejson.Person{
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
				&extractor.Inventory{
					Name:      "acorn",
					Version:   "1.2.2",
					Locations: []string{"testdata/deps/with/deps/acorn/package.json"},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Maintainers: []*packagejson.Person{
							&packagejson.Person{
								Name:  "Marijn Haverbeke",
								Email: "marijnh@gmail.com",
							},
							&packagejson.Person{
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
			name: "Undici package with nonstandard contributors parsed correctly",
			path: "testdata/undici-package.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "undici",
					Version: "5.28.3",
					Locations: []string{
						"testdata/undici-package.json",
					},
					Metadata: &packagejson.JavascriptPackageJSONMetadata{
						Contributors: []*packagejson.Person{
							&packagejson.Person{
								Name: "Daniele Belardi",
								URL:  "https://github.com/dnlup",
							},
							&packagejson.Person{
								Name: "Tomas Della Vedova",
								URL:  "https://github.com/delvedor",
							},
							&packagejson.Person{
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
				&extractor.Inventory{
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
			name:    "invalid packagejson",
			path:    "testdata/invalid",
			wantErr: cmpopts.AnyError,
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

			input := &filesystem.ScanInput{Path: tt.path, Reader: r, Info: info}
			e := packagejson.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(context.Background(), input)
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
		})
	}
}

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg packagejson.Config) packagejson.Config {
	newCfg := packagejson.DefaultConfig()

	if cfg.MaxJSONSize > 0 {
		newCfg.MaxJSONSize = cfg.MaxJSONSize
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
	got, err := e.ToPURL(i)
	if err != nil {
		t.Fatalf("ToPURL(%v): %v", i, err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}
