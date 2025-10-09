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

package nimble_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/nim/nimble"
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
			name:         "nimble file under the pkgs directory",
			path:         "test/.nimble/pkgs/arrayutils-0.2.0/arrayutils.nimble",
			wantRequired: true,
		},
		{
			name:         "nimble file under the pkgs2 directory",
			path:         "test/.nimble/pkgs2/json_serialization-0.4.2-2b26a9e0fc79638dbb9272fb4ab5a1d79264f938/json_serialization.nimble",
			wantRequired: true,
		},
		{
			name:         "nimble file under the pkgs2 directory with non-default installation",
			path:         "test/nimblefolder/pkgs2/stew-0.4.1-996d9c058ee078d0209a5f539424a0235683918c/stew.nimble",
			wantRequired: true,
		},
		{
			name:         "arbitrary file under the pkgs2 directory with no extension",
			path:         "test/.nimble/pkgs2/arrayutils-0.2.0/foo",
			wantRequired: false,
		},
		{
			name:         "nimble file under the wrong director",
			path:         "test/test-01/test.nimble",
			wantRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e filesystem.Extractor = nimble.Extractor{}
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
			name: "valid nimble file path for older versions",
			path: "/root/.nimble/pkgs/arrayutils-0.2.0/arrayutils.nimble",
			wantPackages: []*extractor.Package{
				{
					Name:      "arrayutils",
					Version:   "0.2.0",
					PURLType:  purl.TypeNim,
					Locations: []string{"/root/.nimble/pkgs/arrayutils-0.2.0/arrayutils.nimble"},
				},
			},
		},
		{
			name: "valid nimble file path for newer versions",
			path: "/root/.nimble/pkgs2/libsodium-0.6.0-a2bcc3d783446e393eacf5759dda821f0f714796/libsodium.nimble",
			wantPackages: []*extractor.Package{
				{
					Name:      "libsodium",
					Version:   "0.6.0",
					PURLType:  purl.TypeNim,
					Locations: []string{"/root/.nimble/pkgs2/libsodium-0.6.0-a2bcc3d783446e393eacf5759dda821f0f714796/libsodium.nimble"},
				},
			},
		},
		{
			name: "valid nimble file path with number",
			path: "/root/.nimble/pkgs2/libp2p-1.12.0-336ec68bcd5f13337666dac935007f450a48a9be/libp2p.nimble",
			wantPackages: []*extractor.Package{
				{
					Name:      "libp2p",
					Version:   "1.12.0",
					PURLType:  purl.TypeNim,
					Locations: []string{"/root/.nimble/pkgs2/libp2p-1.12.0-336ec68bcd5f13337666dac935007f450a48a9be/libp2p.nimble"},
				},
			},
		},
		{
			name: "valid nimble path with underscore",
			path: "/root/.nimble/pkgs2/bearssl_pkey_decoder-0.1.0-21b42e2e6ddca6c875d3fc50f36a5115abf51714/bearssl_pkey_decoder.nimble",
			wantPackages: []*extractor.Package{
				{
					Name:      "bearssl_pkey_decoder",
					Version:   "0.1.0",
					PURLType:  purl.TypeNim,
					Locations: []string{"/root/.nimble/pkgs2/bearssl_pkey_decoder-0.1.0-21b42e2e6ddca6c875d3fc50f36a5115abf51714/bearssl_pkey_decoder.nimble"},
				},
			},
		},
		{
			name: "valid nimble path with longer version",
			path: "/root/.nimble/pkgs2/secp256k1-0.6.0.3.2-0cda1744a5d85c872128c50e826b979a6c0f5471/secp256k1.nimble",
			wantPackages: []*extractor.Package{
				{
					Name:      "secp256k1",
					Version:   "0.6.0.3.2",
					PURLType:  purl.TypeNim,
					Locations: []string{"/root/.nimble/pkgs2/secp256k1-0.6.0.3.2-0cda1744a5d85c872128c50e826b979a6c0f5471/secp256k1.nimble"},
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
			var e filesystem.Extractor = nimble.Extractor{}
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
