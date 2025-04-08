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

package packageindex_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/packageindex"
)

var (
	pkgLess = func(i1, i2 *extractor.Package) bool {
		return i1.Name < i2.Name
	}
	sortPKGs        = cmpopts.SortSlices(pkgLess)
	allowUnexported = cmp.AllowUnexported(packagejson.Extractor{}, wheelegg.Extractor{})
)

func TestGetAll(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	pkgs := []*extractor.Package{
		{Name: "software1", Extractor: npmEx},
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}
	want := pkgs

	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New(%v): %v", pkgs, err)
	}

	got := px.GetAll()
	if diff := cmp.Diff(want, got, sortPKGs, allowUnexported); diff != "" {
		t.Errorf("packageindex.New(%v).GetAll(): unexpected package (-want +got):\n%s", pkgs, diff)
	}
}

func TestGetAllOfType(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	pkgs := []*extractor.Package{
		{Name: "software1", Extractor: npmEx},
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}
	want := []*extractor.Package{
		{Name: "software2", Extractor: pipEx},
		{Name: "software3", Extractor: pipEx},
	}

	px, err := packageindex.New(pkgs)
	if err != nil {
		t.Fatalf("packageindex.New(%v): %v", pkgs, err)
	}

	got := px.GetAllOfType("pypi")
	if diff := cmp.Diff(want, got, sortPKGs, allowUnexported); diff != "" {
		t.Errorf("packageindex.New(%v).GetAllOfType(pypi): unexpected package (-want +got):\n%s", pkgs, diff)
	}
}

func TestGetSpecific(t *testing.T) {
	npmEx := packagejson.New(packagejson.DefaultConfig())
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	pkg1 := &extractor.Package{Name: "software1", Version: "1.2.3", Extractor: npmEx}
	pkg2 := &extractor.Package{Name: "software2", Version: "1.2.3", Extractor: pipEx}
	pkg3 := &extractor.Package{Name: "software3", Extractor: pipEx}
	pkg4v123 := &extractor.Package{Name: "software4", Version: "1.2.3", Extractor: npmEx}
	pkg4v456 := &extractor.Package{Name: "software4", Version: "4.5.6", Extractor: npmEx}
	pkgs := []*extractor.Package{pkg1, pkg2, pkg3, pkg4v123, pkg4v456}

	testCases := []struct {
		desc    string
		pkgType string
		pkgName string
		want    []*extractor.Package
	}{
		{
			desc:    "No version or namespace",
			pkgType: "pypi",
			pkgName: "software3",
			want:    []*extractor.Package{pkg3},
		},
		{
			desc:    "software with version",
			pkgType: "pypi",
			pkgName: "software2",
			want:    []*extractor.Package{pkg2},
		},
		{
			desc:    "software with namespace",
			pkgType: "npm",
			pkgName: "software1",
			want:    []*extractor.Package{pkg1},
		},
		{
			desc:    "multiple versions",
			pkgType: "npm",
			pkgName: "software4",
			want:    []*extractor.Package{pkg4v123, pkg4v456},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			px, err := packageindex.New(pkgs)
			if err != nil {
				t.Fatalf("packageindex.New(%v): %v", pkgs, err)
			}

			got := px.GetSpecific(tc.pkgName, tc.pkgType)
			if diff := cmp.Diff(tc.want, got, sortPKGs, allowUnexported); diff != "" {
				t.Errorf("packageindex.New(%v).GetSpecific(%s, %s): unexpected package (-want +got):\n%s", pkgs, tc.pkgName, tc.pkgType, diff)
			}
		})
	}
}
