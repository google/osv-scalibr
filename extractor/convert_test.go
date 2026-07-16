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

package extractor_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	javascriptmeta "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

func TestToPURL(t *testing.T) {
	tests := []struct {
		name    string
		pkg     *extractor.Package
		want    *purl.PackageURL
		wantStr string
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
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath("location"),
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
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeNPM,
				Location: extractor.LocationFromPath("location"),
				Metadata: &javascriptmeta.JavascriptPackageJSONMetadata{
					Source: javascriptmeta.Unknown,
				},
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "Name",
				Version: "1.2.3",
			},
		},
		{
			name: "scoped_npm_purl",
			pkg: &extractor.Package{
				Name:     "@babel/traverse",
				Version:  "7.29.7",
				PURLType: purl.TypeNPM,
				Location: extractor.LocationFromPath("location"),
				Metadata: &javascriptmeta.JavascriptPackageJSONMetadata{
					Source: javascriptmeta.Unknown,
				},
			},
			want: &purl.PackageURL{
				Type:      purl.TypeNPM,
				Namespace: "@babel",
				Name:      "traverse",
				Version:   "7.29.7",
			},
			wantStr: "pkg:npm/%40babel/traverse@7.29.7",
		},
		{
			name: "composer_purl",
			pkg: &extractor.Package{
				Name:     "Symfony/HTTP-Kernel",
				Version:  "8.1.0",
				PURLType: purl.TypeComposer,
				Location: extractor.LocationFromPath("location"),
			},
			want: &purl.PackageURL{
				Type:      purl.TypeComposer,
				Namespace: "symfony",
				Name:      "http-kernel",
				Version:   "8.1.0",
			},
			wantStr: "pkg:composer/symfony/http-kernel@8.1.0",
		},
		{
			name: "hex_purl",
			pkg: &extractor.Package{
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeHex,
				Location: extractor.LocationFromPath("location"),
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
				Location: extractor.LocationFromPath("location"),
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
				Location: extractor.LocationFromPath("location"),
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
				Location: extractor.LocationFromPath("location"),
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
				Location: extractor.LocationFromPath("location"),
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
		{
			name: "github_purl",
			pkg: &extractor.Package{
				Name:     "actions/checkout",
				Version:  "v4",
				PURLType: purl.TypeGithub,
				Location: extractor.LocationFromPath("location"),
			},
			want: &purl.PackageURL{
				Type:      purl.TypeGithub,
				Namespace: "actions",
				Name:      "checkout",
				Version:   "v4",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pkg.PURL()
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("%v.PURL(): unexpected PURL (-want +got):\n%s", tt.pkg, diff)
			}
			if tt.wantStr != "" && got.String() != tt.wantStr {
				t.Errorf("%v.PURL().String() = %q, want %q", tt.pkg, got.String(), tt.wantStr)
			}
		})
	}
}

func TestToEcosystem(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want osvecosystem.Parsed
	}{
		{
			name: "no_purl_type",
			pkg: &extractor.Package{
				Name:    "name",
				Version: "version",
			},
			want: osvecosystem.Parsed{},
		},
		{
			name: "simple_ecosystem",
			pkg: &extractor.Package{
				Name:     "name",
				Version:  "version",
				PURLType: purl.TypeGolang,
			},
			want: osvecosystem.FromEcosystem(osvconstants.EcosystemGo),
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
					OSVersionID:       "11",
					OSID:              "debian",
				},
			},
			want: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemDebian,
				Suffix:    "11",
			},
		},
		{
			name: "dhi_ecosystem",
			pkg: &extractor.Package{
				Name:     "Name",
				Version:  "1.2.3",
				PURLType: purl.TypeDHI,
			},
			want: osvecosystem.FromEcosystem(osvconstants.EcosystemDockerHardenedImages),
		},
		{
			name: "github_actions_ecosystem",
			pkg: &extractor.Package{
				Name:     "actions/checkout",
				Version:  "v4",
				PURLType: purl.TypeGithub,
			},
			want: osvecosystem.FromEcosystem(osvconstants.EcosystemGitHubActions),
		},
		{
			name: "spdx_alpine_ecosystem",
			pkg: &extractor.Package{
				Name:     "nginx",
				Version:  "1.18.0",
				PURLType: purl.TypeApk,
				Metadata: &spdxmeta.Metadata{
					PURL: &purl.PackageURL{
						Type:       purl.TypeApk,
						Namespace:  "alpine",
						Name:       "nginx",
						Version:    "1.18.0",
						Qualifiers: purl.QualifiersFromMap(map[string]string{"distro": "v3.18"}),
					},
				},
			},
			want: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemAlpine,
				Suffix:    "v3.18",
			},
		},
		{
			name: "spdx_debian_ecosystem",
			pkg: &extractor.Package{
				Name:     "nginx",
				Version:  "1.18.0",
				PURLType: purl.TypeDebian,
				Metadata: &spdxmeta.Metadata{
					PURL: &purl.PackageURL{
						Type:       purl.TypeDebian,
						Namespace:  "debian",
						Name:       "nginx",
						Version:    "1.18.0",
						Qualifiers: purl.QualifiersFromMap(map[string]string{"distro": "11"}),
					},
				},
			},
			want: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemDebian,
				Suffix:    "11",
			},
		},
		{
			name: "spdx_ubuntu_ecosystem",
			pkg: &extractor.Package{
				Name:     "nginx",
				Version:  "1.18.0",
				PURLType: purl.TypeDebian,
				Metadata: &spdxmeta.Metadata{
					PURL: &purl.PackageURL{
						Type:       purl.TypeDebian,
						Namespace:  "ubuntu",
						Name:       "nginx",
						Version:    "1.18.0",
						Qualifiers: purl.QualifiersFromMap(map[string]string{"distro": "jammy"}),
					},
				},
			},
			want: osvecosystem.Parsed{
				Ecosystem: osvconstants.EcosystemUbuntu,
				Suffix:    "22.04:LTS",
			},
		},
		{
			name: "brew_ecosystem",
			pkg: &extractor.Package{
				Name:     "pkg-name",
				Version:  "1.2.3",
				PURLType: purl.TypeBrew,
			},
			want: osvecosystem.FromEcosystem(osvconstants.Ecosystem("GIT")),
		},
		{
			name: "git_ecosystem",
			pkg: &extractor.Package{
				Name:     "pkg-name",
				Version:  "1.2.3",
				PURLType: "git",
			},
			want: osvecosystem.FromEcosystem(osvconstants.Ecosystem("GIT")),
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
