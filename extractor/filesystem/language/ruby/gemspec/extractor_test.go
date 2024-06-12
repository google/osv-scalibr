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

package gemspec_test

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
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = gemspec.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "yaml gemspec",
			path:           "testdata/yaml-0.2.1.gemspec",
			wantIsRequired: true,
		},
		{
			name:           "ruby file",
			path:           "testdata/test.rb",
			wantIsRequired: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isRequired := e.FileRequired(test.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(test.path),
				FileMode: fs.ModePerm,
			})
			if isRequired != test.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", test.path, isRequired, test.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = gemspec.Extractor{}

	tests := []struct {
		name          string
		path          string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name: "yaml gemspec",
			path: "testdata/yaml-0.2.1.gemspec",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "yaml",
					Version:   "0.2.1",
					Locations: []string{"testdata/yaml-0.2.1.gemspec"},
				},
			},
		},
		{
			name: "rss gemspec",
			path: "testdata/rss-0.2.9.gemspec",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "rss",
					Version:   "0.2.9",
					Locations: []string{"testdata/rss-0.2.9.gemspec"},
				},
			},
		},
		{
			name:    "invalid gemspec",
			path:    "testdata/invalid.gemspec",
			wantErr: cmpopts.AnyError,
		},
		{
			name:          "empty gemspec",
			path:          "testdata/empty.gemspec",
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "bad definition gemspec",
			path:          "testdata/badspec.gemspec",
			wantInventory: []*extractor.Inventory{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := os.Open(test.path)
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			input := &filesystem.ScanInput{Path: test.path, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", test.name, err, test.wantErr)
			}

			var want []*extractor.Inventory
			if test.wantInventory != nil {
				want = test.wantInventory
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract(%+v) diff (-want +got):\n%s", test.name, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := gemspec.Extractor{}
	i := &extractor.Inventory{
		Name:      "name",
		Version:   "1.2.3",
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:    purl.TypeGem,
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
