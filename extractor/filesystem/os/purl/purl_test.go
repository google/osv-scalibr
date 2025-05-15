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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	ospurl "github.com/google/osv-scalibr/extractor/filesystem/os/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURLDebian(t *testing.T) {
	pkgname := "pkgname"
	sourcename := "sourcename"
	version := "1.2.3"
	sourceversion := "1.2.4"
	source := "sourcename"
	tests := []struct {
		name     string
		purlType string
		metadata *dpkgmeta.Metadata
		want     *purl.PackageURL
	}{
		{
			name:     "both OS versions present",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSID:              "debian",
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			name:     "only VERSION_ID set",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:   pkgname,
				SourceName:    sourcename,
				SourceVersion: sourceversion,
				OSID:          "debian",
				OSVersionID:   "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "debian",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "22.04",
				}),
			},
		},
		{
			name:     "ID not set, fallback to linux",
			purlType: purl.TypeDebian,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				SourceName:        sourcename,
				SourceVersion:     sourceversion,
				OSVersionCodename: "jammy",
				OSVersionID:       "22.04",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeDebian,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Source:        source,
					purl.SourceVersion: sourceversion,
					purl.Distro:        "jammy",
				}),
			},
		},
		{
			name:     "OS ID and OS Version set (OpenWrt)",
			purlType: purl.TypeOpkg,
			metadata: &dpkgmeta.Metadata{
				PackageName: pkgname,
				OSID:        "openwrt",
				OSVersionID: "22.03.5",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "openwrt",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "22.03.5",
				}),
			},
		},
		{
			name:     "OS ID not set, fallback to linux",
			purlType: purl.TypeOpkg,
			metadata: &dpkgmeta.Metadata{
				PackageName:       pkgname,
				OSVersionCodename: "jammy",
				OSVersionID:       "5.10",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeOpkg,
				Name:      pkgname,
				Namespace: "linux",
				Version:   version,
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.Distro: "jammy",
				}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ospurl.MakePackageURL(tt.name, version, tt.purlType, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("ospurl.MakePackageURL(%v, %v, %v, %v): unexpected PURL (-want +got):\n%s", tt.name, version, tt.purlType, tt.metadata, diff)
			}
		})
	}
}
