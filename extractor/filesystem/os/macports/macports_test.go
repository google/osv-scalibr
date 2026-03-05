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

package macports_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macports"
	macportsmeta "github.com/google/osv-scalibr/extractor/filesystem/os/macports/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid portfile",
			path:         "/opt/local/var/macports/registry/portfiles/libtool-2.5.4_0/ad1db8600defd0eb7646fd461154434ec33014e5b04be396c9a40b0ce9171299-2968/Portfile",
			wantRequired: true,
		},
		{
			name:         "invalid portfile folder on version",
			path:         "/opt/local/var/macports/registry/portfiles/autoconf-0/1f197df6a061a6661dd5b6292a0e88d6b31d81b6927563a17530cbab5706723c-2566/Portfile",
			wantRequired: false,
		},
		{
			name:         "invalid portfile folder on revision",
			path:         "/opt/local/var/macports/registry/portfiles/freetype-2.13.3/801278d1d6f986fb9d249bf7320528c70d057280593ff462a9f425a58d9f269c-4310/Portfile",
			wantRequired: false,
		},
		{
			name:         "invalid portfile folder on sha256 hash",
			path:         "/opt/local/var/macports/registry/portfiles/brotli-1.1.0_0/23-2335/Portfile",
			wantRequired: false,
		},
		{
			name:         "invalid portfile folder on index",
			path:         "/opt/local/var/macports/registry/portfiles/gmp-6.3.0_0/8ae36d8bcd724fe086917092efbde6a5d50b0401381fa67a45978c92fb042b96/Portfile",
			wantRequired: false,
		},
		{
			name:         "invalid portfile name",
			path:         "/opt/local/var/macports/registry/portfiles/pango-1.55.0_0/b333af837d8e7245cf81b35c1b9ef384cc327b85a48f5ce7eaa72110103eff8a-5916/PortfileXXX",
			wantRequired: false,
		},
		{
			name:         "invalid folder path",
			path:         "/opt/local/var/macports/registry/portfile/x/y",
			wantRequired: false,
		},
		{
			name:         "invalid folder path",
			path:         "/opt/local/var/macports/registry/portfiles_dummy/pango-1.55.0_0/2323-5916/Portfile",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := macports.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("macports.New: %v", err)
			}
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func pkgLess(i1, i2 *extractor.Package) bool {
	return i1.Name < i2.Name
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantPackages []*extractor.Package
		wantErr      error
	}{
		{
			name: "valid_portfile_path",
			path: "/opt/local/var/macports/registry/portfiles/libtool-2.5.4_0/ad1db8600defd0eb7646fd461154434ec33014e5b04be396c9a40b0ce9171299-2968/Portfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "libtool",
					Version:  "2.5.4",
					PURLType: purl.TypeMacports,
					Metadata: &macportsmeta.Metadata{
						PackageName:     "libtool",
						PackageVersion:  "2.5.4",
						PackageRevision: "0",
					},
					Locations: []string{"/opt/local/var/macports/registry/portfiles/libtool-2.5.4_0/ad1db8600defd0eb7646fd461154434ec33014e5b04be396c9a40b0ce9171299-2968/Portfile"},
				},
			},
		},
		{
			name: "valid_portfile_path_with_a_dash_in_it",
			path: "/opt/local/var/macports/registry/portfiles/gobject-introspection-1.78.1_5/c55084712bbb40ccf96cbfb8f1c1c77c670a37e189f4accb8ada691aea18d1ef-1331/Portfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "gobject-introspection",
					Version:  "1.78.1",
					PURLType: purl.TypeMacports,
					Metadata: &macportsmeta.Metadata{
						PackageName:     "gobject-introspection",
						PackageVersion:  "1.78.1",
						PackageRevision: "5",
					},
					Locations: []string{"/opt/local/var/macports/registry/portfiles/gobject-introspection-1.78.1_5/c55084712bbb40ccf96cbfb8f1c1c77c670a37e189f4accb8ada691aea18d1ef-1331/Portfile"},
				},
			},
		},
		{
			name: "valid_portfile_path_with_two_dashes_in_it",
			path: "/opt/local/var/macports/registry/portfiles/xorg-xcb-proto-1.17.0_0/9846ecdbb454aa6ef08a26553a3667b63a6f46abfdb73ffaec2700e6473074df-2685/Portfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "xorg-xcb-proto",
					Version:  "1.17.0",
					PURLType: purl.TypeMacports,
					Metadata: &macportsmeta.Metadata{
						PackageName:     "xorg-xcb-proto",
						PackageVersion:  "1.17.0",
						PackageRevision: "0",
					},
					Locations: []string{"/opt/local/var/macports/registry/portfiles/xorg-xcb-proto-1.17.0_0/9846ecdbb454aa6ef08a26553a3667b63a6f46abfdb73ffaec2700e6473074df-2685/Portfile"},
				},
			},
		},
		{
			name: "valid_portfile_path_with_number_in_the_package_name",
			path: "/opt/local/var/macports/registry/portfiles/gd2-2.3.3_7/6c29fb21ddd646407e905e6b8b9a2c70cf00b3dea10609043f6b188fa7e30a1b-3596/Portfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "gd2",
					Version:  "2.3.3",
					PURLType: purl.TypeMacports,
					Metadata: &macportsmeta.Metadata{
						PackageName:     "gd2",
						PackageVersion:  "2.3.3",
						PackageRevision: "7",
					},
					Locations: []string{"/opt/local/var/macports/registry/portfiles/gd2-2.3.3_7/6c29fb21ddd646407e905e6b8b9a2c70cf00b3dea10609043f6b188fa7e30a1b-3596/Portfile"},
				},
			},
		},
		{
			name: "valid_portfile_path_with_text_in_the_version_part",
			path: "/opt/local/var/macports/registry/portfiles/urw-fonts-1.0.7pre44_0/07082b6c0b422e34867886e9af30145d0ffaf7e8586705677a9906c1fd8a314f-1753/Portfile",
			wantPackages: []*extractor.Package{
				{
					Name:     "urw-fonts",
					Version:  "1.0.7pre44",
					PURLType: purl.TypeMacports,
					Metadata: &macportsmeta.Metadata{
						PackageName:     "urw-fonts",
						PackageVersion:  "1.0.7pre44",
						PackageRevision: "0",
					},
					Locations: []string{"/opt/local/var/macports/registry/portfiles/urw-fonts-1.0.7pre44_0/07082b6c0b422e34867886e9af30145d0ffaf7e8586705677a9906c1fd8a314f-1753/Portfile"},
				},
			},
		},
		{
			name:         "invalid path",
			path:         "/tmp/var/scalibr",
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := macports.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("macports.New: %v", err)
			}
			input := &filesystem.ScanInput{Path: tt.path, Reader: nil}
			got, err := e.Extract(t.Context(), input)
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract(%s) unexpected error (-want +got):\n%s", tt.path, diff)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(pkgLess)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
