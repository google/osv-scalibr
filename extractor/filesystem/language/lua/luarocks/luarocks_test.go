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

package luarocks_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/lua/luarocks"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid .rockspec file with Lua 5.4",
			path:         "/test/rocks-5.4/aesfileencrypt/0.1.3-1/aesfileencrypt-0.1.3-1.rockspec",
			wantRequired: true,
		},
		{
			name:         "valid .rockspec file with Lua 5.2",
			path:         "/test/rocks-5.2/aesfileencrypt/0.1.3-1/aesfileencrypt-0.1.3-1.rockspec",
			wantRequired: true,
		},
		{
			name:         ".rockspec file with missing folder",
			path:         "/test/rocks-5.2/0.1.3-1/aesfileencrypt-0.1.3-1.rockspec",
			wantRequired: false,
		},
		{
			name:         "ordinary text file without correct extension",
			path:         "/test/rocks-5.4/aesfileencrypt/0.1.3-1/rock_manifest",
			wantRequired: false,
		},
		{
			name:         "ordinary Lua file without correct extension",
			path:         "/test/rocks-5.4/aesfileencrypt/0.1.3-1/test/test.lua",
			wantRequired: false,
		},
		{
			name:         ".rockspec file in the wrong path",
			path:         "/test/aesfileencrypt/0.1.3-1/test/test.lua",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = luarocks.Extractor{}
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
			name: "valid .rockspec file path for the latest version",
			path: "testdata/rocks-5.4/aesfileencrypt/0.1.3-1/aesfileencrypt-0.1.3-1.rockspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "aesfileencrypt",
					Version:   "0.1.3-1",
					PURLType:  purl.TypeLua,
					Locations: []string{"testdata/rocks-5.4/aesfileencrypt/0.1.3-1/aesfileencrypt-0.1.3-1.rockspec"},
				},
			},
		},
		{
			name: "valid .rockspec file path for an old version",
			path: "testdata/rocks-5.2/lua-resty-jwt/0.2.3-0/lua-resty-jwt-0.2.3-0.rockspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "lua-resty-jwt",
					Version:   "0.2.3-0",
					PURLType:  purl.TypeLua,
					Locations: []string{"testdata/rocks-5.2/lua-resty-jwt/0.2.3-0/lua-resty-jwt-0.2.3-0.rockspec"},
				},
			},
		},
		{
			name: "valid .rockspec file path with string version",
			path: "testdata/rocks-5.4/gversion/dev-0/gversion-dev-0.rockspec",
			wantPackages: []*extractor.Package{
				{
					Name:      "gversion",
					Version:   "dev-0",
					PURLType:  purl.TypeLua,
					Locations: []string{"testdata/rocks-5.4/gversion/dev-0/gversion-dev-0.rockspec"},
				},
			},
		},
		{
			name:         "invalid path",
			path:         "/gversion/dev-0/gversion-dev-0.rockspec",
			wantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = luarocks.Extractor{}
			input := &filesystem.ScanInput{Path: tt.path, Reader: nil}
			got, err := e.Extract(context.Background(), input)
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
