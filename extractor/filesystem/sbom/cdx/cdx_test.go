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

package cdx_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = cdx.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "sbom.cdx.json",
			path:           "testdata/sbom.cdx.json",
			wantIsRequired: true,
		},
		{
			name:           "sbom.cdx.JSON",
			path:           "testdata/sbom.cdx.JSON",
			wantIsRequired: true,
		},
		{
			name:           "sbom.cDX.json",
			path:           "testdata/sbom.cDX.json",
			wantIsRequired: true,
		},
		{
			name:           "sbom.bom.json",
			path:           "testdata/sbom.bom.json",
			wantIsRequired: false,
		},
		{
			name:           "sbom.bom.xml",
			path:           "testdata/sbom.bom.xml",
			wantIsRequired: false,
		},
		{
			name:           "bom.json",
			path:           "testdata/bom.json",
			wantIsRequired: true,
		},
		{
			name:           "bom.xml",
			path:           "testdata/bom.xml",
			wantIsRequired: true,
		},
		{
			name:           "sbom.cdx.xml",
			path:           "testdata/sbom.cdx.xml",
			wantIsRequired: true,
		},
		{
			name:           "random_file.ext",
			path:           "testdata/random_file.ext",
			wantIsRequired: false,
		},
		{
			name:           "sbom.cdx.json.foo.ext",
			path:           "testdata/sbom.cdx.json.foo.ext",
			wantIsRequired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	var e filesystem.Extractor = cdx.Extractor{}

	tests := []struct {
		name         string
		path         string
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			name:         "minimal.cdx.json",
			path:         "testdata/minimal.cdx.json",
			wantPackages: []*extractor.Package{},
		},
		{
			name: "sbom.cdx.json",
			path: "testdata/sbom.cdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:    "Nginx",
					Version: "1.21.1",
					Metadata: &cdxmeta.Metadata{
						CPEs: []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
					},
					Locations: []string{"testdata/sbom.cdx.json"},
				},
				{
					Name:     "openssl",
					Version:  "1.1.1",
					PURLType: purl.TypeGeneric,
					Metadata: &cdxmeta.Metadata{
						PURL: purlFromString(t, "pkg:generic/openssl@1.1.1"),
					},
					Locations: []string{"testdata/sbom.cdx.json"},
				},
			},
		},
		{
			name: "sbom-with-nested-comps.cdx.json",
			path: "testdata/sbom-with-nested-comps.cdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:    "Nginx",
					Version: "1.21.1",
					Metadata: &cdxmeta.Metadata{
						CPEs: []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
					},
					Locations: []string{"testdata/sbom-with-nested-comps.cdx.json"},
				},
				{
					Name:     "openssl",
					Version:  "1.1.1",
					PURLType: purl.TypeGeneric,
					Metadata: &cdxmeta.Metadata{
						PURL: purlFromString(t, "pkg:generic/openssl@1.1.1"),
					},
					Locations: []string{"testdata/sbom-with-nested-comps.cdx.json"},
				},
				{
					Name:     "rustls",
					Version:  "0.23.13",
					PURLType: purl.TypeCargo,
					Metadata: &cdxmeta.Metadata{
						PURL: purlFromString(t, "pkg:cargo/rustls@0.23.13"),
					},
					Locations: []string{"testdata/sbom-with-nested-comps.cdx.json"},
				},
			},
		},
		{
			name: "sbom-with-locations.cdx.json",
			path: "testdata/sbom-with-locations.cdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "@gar/promisify",
					Version:  "1.1.3",
					PURLType: purl.TypeNPM,
					Metadata: &cdxmeta.Metadata{
						PURL: purlFromString(t, "pkg:npm/%40gar%2Fpromisify@1.1.3"),
						CDXLocations: []string{
							"home/test/.vscode-server/bin/node_modules/@gar/promisify/package.json",
							"usr/lib/node_modules/@gar/promisify/package.json",
						},
					},
					Locations: []string{
						"testdata/sbom-with-locations.cdx.json",
					},
				},
			},
		},
		{
			name: "sbom.cdx.xml",
			path: "testdata/sbom.cdx.xml",
			wantPackages: []*extractor.Package{
				{
					Name:    "Nginx",
					Version: "1.21.1",
					Metadata: &cdxmeta.Metadata{
						CPEs: []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
					},
					Locations: []string{"testdata/sbom.cdx.xml"},
				},
				{
					Name:     "openssl",
					Version:  "1.1.1",
					PURLType: purl.TypeGeneric,
					Metadata: &cdxmeta.Metadata{
						PURL: purlFromString(t, "pkg:generic/openssl@1.1.1"),
					},
					Locations: []string{"testdata/sbom.cdx.xml"},
				},
			},
		},
		{
			name:    "invalid_sbom.cdx.json",
			path:    "testdata/invalid_sbom.cdxjson",
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "sbom.cdx.json.foo.ext",
			path:    "testdata/sbom.cdx.json.foo.ext",
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

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Reader: r}
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

func pkgLess(i1, i2 *extractor.Package) bool {
	return i1.Name < i2.Name
}

func purlFromString(t *testing.T, purlStr string) *purl.PackageURL {
	t.Helper()

	res, err := purl.FromString(purlStr)
	if err != nil {
		t.Fatalf("purlFromString(%s): %v", purlStr, err)
	}
	return &res
}
