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

package inventoryindex_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventoryindex"
)

var (
	invLess = func(i1, i2 *extractor.Inventory) bool {
		return i1.Name < i2.Name
	}
	sortInv         = cmpopts.SortSlices(invLess)
	allowUnexported = cmp.AllowUnexported(packagejson.Extractor{}, wheelegg.Extractor{})
)

func TestGetAll(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	inv := []*extractor.Inventory{
		{Name: "software1", Extractor: npmEx},
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}
	want := inv

	ix, err := inventoryindex.New(inv)
	if err != nil {
		t.Fatalf("inventoryindex.New(%v): %v", inv, err)
	}

	got := ix.GetAll()
	if diff := cmp.Diff(want, got, sortInv, allowUnexported); diff != "" {
		t.Errorf("inventoryindex.New(%v).GetAll(): unexpected inventory (-want +got):\n%s", inv, diff)
	}
}

func TestGetAllOfType(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	inv := []*extractor.Inventory{
		{Name: "software1", Extractor: npmEx},
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}
	want := []*extractor.Inventory{
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}

	ix, err := inventoryindex.New(inv)
	if err != nil {
		t.Fatalf("inventoryindex.New(%v): %v", inv, err)
	}

	got := ix.GetAllOfType("pypi")
	if diff := cmp.Diff(want, got, sortInv, allowUnexported); diff != "" {
		t.Errorf("inventoryindex.New(%v).GetAllOfType(pypi): unexpected inventory (-want +got):\n%s", inv, diff)
	}
}

func TestGetSpecific(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	inv1 := &extractor.Inventory{Name: "software1", Version: "1.2.3", Extractor: npmEx}
	inv2 := &extractor.Inventory{Name: "software2", Version: "1.2.3", Extractor: pipEx}
	inv3 := &extractor.Inventory{Name: "software3", Extractor: pipEx}
	inv4v123 := &extractor.Inventory{Name: "software4", Version: "1.2.3", Extractor: npmEx}
	inv4v456 := &extractor.Inventory{Name: "software4", Version: "4.5.6", Extractor: npmEx}
	inv := []*extractor.Inventory{inv1, inv2, inv3, inv4v123, inv4v456}

	testCases := []struct {
		desc    string
		pkgType string
		pkgName string
		want    []*extractor.Inventory
	}{
		{
			desc:    "No version or namespace",
			pkgType: "pypi",
			pkgName: "software3",
			want:    []*extractor.Inventory{inv3},
		},
		{
			desc:    "software with version",
			pkgType: "pypi",
			pkgName: "software2",
			want:    []*extractor.Inventory{inv2},
		},
		{
			desc:    "software with namespace",
			pkgType: "npm",
			pkgName: "software1",
			want:    []*extractor.Inventory{inv1},
		},
		{
			desc:    "multiple versions",
			pkgType: "npm",
			pkgName: "software4",
			want:    []*extractor.Inventory{inv4v123, inv4v456},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ix, err := inventoryindex.New(inv)
			if err != nil {
				t.Fatalf("inventoryindex.New(%v): %v", inv, err)
			}

			got := ix.GetSpecific(tc.pkgName, tc.pkgType)
			if diff := cmp.Diff(tc.want, got, sortInv, allowUnexported); diff != "" {
				t.Errorf("inventoryindex.New(%v).GetSpecific(%s, %s): unexpected inventory (-want +got):\n%s", inv, tc.pkgName, tc.pkgType, diff)
			}
		})
	}
}
