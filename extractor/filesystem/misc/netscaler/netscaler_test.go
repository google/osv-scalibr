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

package netscaler_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/netscaler"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	extractor := netscaler.New()
	tests := []struct {
		path string
		want bool
	}{
		{"testdata/ns.conf", true},
		{"testdata/loader.conf", true},
		{"testdata/nsversion", true},
		{"testdata/document.txt", false},
		{"testdata/noextension", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := extractor.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e = netscaler.New()

	tests := []struct {
		name         string
		path         string
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			name: "NetScaler",
			path: filepath.Join("testdata", "valid", "loader.conf"),
			wantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					PURLType:  purl.TypeNetScaler,
					Version:   "14.1-36.5",
					Locations: []string{filepath.Join("testdata", "valid", "loader.conf")},
					Metadata:  os.DirFS(".").(scalibrfs.FS),
				},
			},
		},
		{
			name: "NetScaler",
			path: filepath.Join("testdata", "valid", "nsversion"),
			wantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					PURLType:  purl.TypeNetScaler,
					Version:   "13.1-59.21",
					Locations: []string{filepath.Join("testdata", "valid", "nsversion")},
					Metadata:  os.DirFS(".").(scalibrfs.FS),
				},
			},
		},
		{
			name: "NetScaler",
			path: filepath.Join("testdata", "valid", "ns.conf"),
			wantPackages: []*extractor.Package{
				{
					Name:      "NetScaler",
					PURLType:  purl.TypeNetScaler,
					Version:   "12.1-55.329",
					Locations: []string{filepath.Join("testdata", "valid", "ns.conf")},
					Metadata:  os.DirFS(".").(scalibrfs.FS),
				},
			},
		},
		{
			name:         "NetScaler",
			path:         filepath.Join("testdata", "invalid", "loader.conf"),
			wantPackages: nil,
		},
		{
			name:         "NetScaler",
			path:         filepath.Join("testdata", "invalid", "nsversion"),
			wantPackages: nil,
		},
		{
			name:         "NetScaler",
			path:         filepath.Join("testdata", "invalid", "ns.conf"),
			wantPackages: nil,
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

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Reader: r}
			got, err := e.Extract(t.Context(), input)
			if diff := cmp.Diff(tt.wantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Extract(%s) unexpected error (-want +got):\n%s", tt.path, diff)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}
