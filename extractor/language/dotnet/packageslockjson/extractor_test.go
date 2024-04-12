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

package packageslockjson_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e extractor.InventoryExtractor = packageslockjson.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "some project's packages.lock.json",
			path:           "project/packages.lock.json",
			wantIsRequired: true,
		},

		{
			name:           "just packages.lock.json",
			path:           "packages.lock.json",
			wantIsRequired: true,
		},
		{
			name:           "non packages.lock.json",
			path:           "project/some.csproj",
			wantIsRequired: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isRequired := e.FileRequired(test.path, 0)
			if isRequired != test.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", test.path, isRequired, test.wantIsRequired)
			}
		})
	}
}

func TestExtractor(t *testing.T) {
	var e extractor.InventoryExtractor = packageslockjson.Extractor{}
	tests := []struct {
		name          string
		path          string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name: "valid packages.lock.json",
			path: "testdata/valid/packages.lock.json",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:      "Core.Dep",
					Version:   "1.24.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Dep.One",
					Version:   "1.1.1",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Dep.Two",
					Version:   "4.6.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Dep.Three",
					Version:   "1.0.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Dep.Four",
					Version:   "4.5.0",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Longer.Name.Dep",
					Version:   "4.7.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Some.Dep.Five",
					Version:   "4.7.2",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
				&extractor.Inventory{
					Name:      "Another.Longer.Name.Dep",
					Version:   "4.5.4",
					Locations: []string{"testdata/valid/packages.lock.json"},
					Extractor: packageslockjson.Name,
				},
			},
		},
		{
			name:    "non json input",
			path:    "testdata/invalid/invalid",
			wantErr: cmpopts.AnyError,
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

			input := &extractor.ScanInput{Path: test.path, Reader: r}
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", test.name, err, test.wantErr)
			}

			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(test.wantInventory, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", test.path, diff)
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := packageslockjson.Extractor{}
	i := &extractor.Inventory{
		Name:      "Name",
		Version:   "1.2.3",
		Locations: []string{"location"},
		Extractor: packageslockjson.Name,
	}
	want := &purl.PackageURL{
		Type:    purl.TypeNuget,
		Name:    "Name",
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
