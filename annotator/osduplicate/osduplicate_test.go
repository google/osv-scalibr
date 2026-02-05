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

package osduplicate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/annotator/osduplicate"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
)

func TestBuildLocationToPKGsMap(t *testing.T) {
	tests := []struct {
		desc      string
		inventory *inventory.Inventory
		scanRoot  string
		want      map[string][]*extractor.Package
	}{
		{
			desc:      "empty_inventory",
			inventory: &inventory.Inventory{},
			want:      map[string][]*extractor.Package{},
		},
		{
			desc: "one_pkg_per_location",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "package1", Locations: []string{"location1"}},
					{Name: "package2", Locations: []string{"location2"}},
				},
			},
			want: map[string][]*extractor.Package{
				"location1": []*extractor.Package{{Name: "package1", Locations: []string{"location1"}}},
				"location2": []*extractor.Package{{Name: "package2", Locations: []string{"location2"}}},
			},
		},
		{
			desc: "multiple_pkgs_per_location",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "package1", Locations: []string{"location"}},
					{Name: "package2", Locations: []string{"location"}},
				},
			},
			want: map[string][]*extractor.Package{
				"location": []*extractor.Package{
					{Name: "package1", Locations: []string{"location"}},
					{Name: "package2", Locations: []string{"location"}},
				},
			},
		},
		{
			desc: "ignore_non_lockfile_locations",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "package", Locations: []string{"lockfile", "non-lockfile"}},
				},
			},
			want: map[string][]*extractor.Package{
				"lockfile": []*extractor.Package{{Name: "package", Locations: []string{"lockfile", "non-lockfile"}}},
			},
		},
		{
			desc: "ignore_os_packages",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "os-package", Locations: []string{"location-1"}, Plugins: []string{"os/dpkg"}},
					{Name: "language-package", Locations: []string{"location-2"}, Plugins: []string{"python/wheelegg"}},
				},
			},
			want: map[string][]*extractor.Package{
				"location-2": []*extractor.Package{{Name: "language-package", Locations: []string{"location-2"}, Plugins: []string{"python/wheelegg"}}},
			},
		},
		{
			desc: "absolute_to_relative_paths",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "package1", Locations: []string{"/root/location1"}},
					{Name: "package2", Locations: []string{"/root/location2"}},
				},
			},
			scanRoot: "/root/",
			want: map[string][]*extractor.Package{
				"location1": []*extractor.Package{{Name: "package1", Locations: []string{"/root/location1"}}},
				"location2": []*extractor.Package{{Name: "package2", Locations: []string{"/root/location2"}}},
			},
		},
		{
			desc: "absolute_to_relative_paths_no_leading_slash",
			inventory: &inventory.Inventory{
				Packages: []*extractor.Package{
					{Name: "package1", Locations: []string{"/root/location1"}},
					{Name: "package2", Locations: []string{"/root/location2"}},
				},
			},
			scanRoot: "/root",
			want: map[string][]*extractor.Package{
				"location1": []*extractor.Package{{Name: "package1", Locations: []string{"/root/location1"}}},
				"location2": []*extractor.Package{{Name: "package2", Locations: []string{"/root/location2"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := osduplicate.BuildLocationToPKGsMap(tt.inventory, &scalibrfs.ScanRoot{Path: tt.scanRoot})

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("BuildLocationToPKGsMap(%v): unexpected diff (-want +got): %v", tt.inventory, diff)
			}
		})
	}
}
