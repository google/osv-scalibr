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

package extractor_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/purl"
)

func TestToPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want *purl.PackageURL
	}{
		{
			name: "no_purl_type",
			pkg: &extractor.Package{
				Name:    "name",
				Version: "version",
			},
			want: nil,
		},
		{
			name: "simple_purl",
			pkg: &extractor.Package{
				Name:     "name",
				Version:  "version",
				PURLType: purl.TypeGolang,
			},
			want: &purl.PackageURL{
				Type:    purl.TypeGolang,
				Name:    "name",
				Version: "version",
			},
		},
		{
			name: "python_purl",
			pkg: &extractor.Package{
				Name:      "Name",
				Version:   "1.2.3",
				PURLType:  purl.TypePyPi,
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:    purl.TypePyPi,
				Name:    "name",
				Version: "1.2.3",
			},
		},
		{
			name: "npm_purl",
			pkg: &extractor.Package{
				Name:      "Name",
				Version:   "1.2.3",
				PURLType:  purl.TypeNPM,
				Locations: []string{"location"},
				Metadata: &javascriptmeta.JavascriptPackageJSONMetadata{
					FromNPMRepository: false,
				},
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "Name",
				Version: "1.2.3",
			},
		},
		{
			name: "hex_purl",
			pkg: &extractor.Package{
				Name:      "Name",
				Version:   "1.2.3",
				PURLType:  purl.TypeHex,
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:    purl.TypeHex,
				Name:    "name",
				Version: "1.2.3",
			},
		},
		{
			name: "spdx_purl",
			pkg: &extractor.Package{
				Name:     "name",
				PURLType: purl.TypePyPi,
				Metadata: &spdxmeta.Metadata{
					PURL: &purl.PackageURL{
						Type:      purl.TypePyPi,
						Name:      "name",
						Namespace: "namespace",
						Version:   "1.2.3",
					},
					CPEs: []string{},
				},
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:      purl.TypePyPi,
				Name:      "name",
				Namespace: "namespace",
				Version:   "1.2.3",
			},
		},
		{
			name: "cdx_purl",
			pkg: &extractor.Package{
				Name:     "name",
				PURLType: purl.TypeCargo,
				Metadata: &cdxmeta.Metadata{
					PURL: &purl.PackageURL{
						Type:      purl.TypeCargo,
						Name:      "name",
						Namespace: "namespace",
						Version:   "1.2.3",
					},
					CPEs: []string{},
				},
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:      purl.TypeCargo,
				Name:      "name",
				Namespace: "namespace",
				Version:   "1.2.3",
			},
		},
		{
			name: "dpkg_purl",
			pkg: &extractor.Package{
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmeta.Metadata{
					PackageName:       "pkg-name",
					OSVersionCodename: "jammy",
				},
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Namespace: "linux",
				Name:      "pkg-name",
				Version:   "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
		{
			name: "opkg_purl",
			pkg: &extractor.Package{
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeOpkg,
				Metadata: &dpkgmeta.Metadata{
					PackageName:       "pkg-name",
					OSVersionCodename: "jammy",
				},
				Locations: []string{"location"},
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Namespace: "linux",
				Name:      "pkg-name",
				Version:   "1.2.3",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkg.PURL()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("%v.PURL(): unexpected PURL (-want +got):\n%s", tt.pkg, diff)
			}
		})
	}
}

func TestToEcosystem(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want string
	}{
		{
			name: "no_purl_type",
			pkg: &extractor.Package{
				Name:    "name",
				Version: "version",
			},
			want: "",
		},
		{
			name: "simple_ecosystem",
			pkg: &extractor.Package{
				Name:     "name",
				Version:  "version",
				PURLType: purl.TypeGolang,
			},
			want: "Go",
		},
		{
			name: "os_ecosystem",
			pkg: &extractor.Package{
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeDebian,
				Metadata: &dpkgmeta.Metadata{
					PackageName:       "pkg-name",
					OSVersionCodename: "jammy",
				},
			},
			want: "Linux",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkg.Ecosystem()
			if got != tt.want {
				t.Errorf("%v.Ecosystem(): got %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}
