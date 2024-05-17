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

package packagelockjson_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = packagelockjson.Extractor{}

	tests := []struct {
		path string
		want bool
	}{
		{path: "foo/package-lock.json", want: true},
		{path: "foo/package.json", want: false},
		{path: "foo/asdf.json", want: false},
		{path: "foo-package-lock.json", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			isRequired := e.FileRequired(tt.path, 0)
			if isRequired != tt.want {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = packagelockjson.Extractor{}

	tests := []struct {
		name          string
		path          string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name: "package-lock.v1",
			path: "testdata/package-lock.v1.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"testdata/package-lock.v1.json"},
				},
				&extractor.Inventory{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"testdata/package-lock.v1.json"},
				},
			},
		},
		{
			name: "package-lock.v2",
			path: "testdata/package-lock.v2.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "wrappy",
					Version:   "1.0.2",
					Locations: []string{"testdata/package-lock.v2.json"},
				},
				&extractor.Inventory{
					Name:      "supports-color",
					Version:   "5.5.0",
					Locations: []string{"testdata/package-lock.v2.json"},
				},
			},
		},
		{
			name:    "invalid json",
			path:    "testdata/invalid.json",
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "not json",
			path:    "testdata/notjson",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
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

			input := &filesystem.ScanInput{Path: tt.path, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.name, err, tt.wantErr)
			}

			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantInventory, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := packagelockjson.Extractor{}
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
