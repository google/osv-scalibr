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
	"github.com/google/osv-scalibr/purl"
	"github.com/package-url/packageurl-go"
)

func TestFromString(t *testing.T) {
	tests := []struct {
		name string
		purl string
		want purl.PackageURL
	}{
		// Tests should be ordered by type as they appear in
		// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#cargo
		{
			name: "bitbucket",
			purl: "pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c",
			want: purl.PackageURL{
				Type:      "bitbucket",
				Namespace: "birkenfeld",
				Name:      "pygments-main",
				Version:   "244fd47e07d1014f0aed9c",
			},
		}, {
			name: "cargo",
			purl: "pkg:cargo/rand@0.7.2",
			want: purl.PackageURL{
				Type:    "cargo",
				Name:    "rand",
				Version: "0.7.2",
			},
		}, {
			name: "composer",
			purl: "pkg:composer/laravel/laravel@5.5.0",
			want: purl.PackageURL{
				Type:      "composer",
				Namespace: "laravel",
				Name:      "laravel",
				Version:   "5.5.0",
			},
		}, {
			name: "deb",
			purl: "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie",
			want: purl.PackageURL{
				Type:       "deb",
				Namespace:  "debian",
				Name:       "curl",
				Version:    "7.50.3-1",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "i386", "distro": "jessie"}),
			},
		}, {
			name: "gem",
			purl: "pkg:gem/jruby-launcher@1.1.2?platform=java",
			want: purl.PackageURL{
				Type:       "gem",
				Name:       "jruby-launcher",
				Version:    "1.1.2",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"platform": "java"}),
			},
		}, {
			name: "github",
			purl: "pkg:github/package-url/purl-spec@244fd47e07d1004#everybody/loves/dogs",
			want: purl.PackageURL{
				Type:      "github",
				Namespace: "package-url",
				Name:      "purl-spec",
				Version:   "244fd47e07d1004",
				Subpath:   "everybody/loves/dogs",
			},
		}, {
			name: "golang",
			purl: "pkg:golang/package-name@1.2.3",
			want: purl.PackageURL{
				Type:    "golang",
				Name:    "package-name",
				Version: "1.2.3",
			},
		}, {
			name: "maven",
			purl: "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?classifier=dist&type=zip",
			want: purl.PackageURL{
				Type:       "maven",
				Namespace:  "org.apache.xmlgraphics",
				Name:       "batik-anim",
				Version:    "1.9.1",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"classifier": "dist", "type": "zip"}),
			},
		}, {
			name: "npm",
			purl: "pkg:npm/foobar@12.3.1",
			want: purl.PackageURL{
				Type:    "npm",
				Name:    "foobar",
				Version: "12.3.1",
			},
		}, {
			name: "rpm",
			purl: "pkg:rpm/fedora/curl@7.50.3-1.fc25?arch=i386&distro=fedora-25&sourcerpm=curl-7.50.3-1.fc25.src.rpm",
			want: purl.PackageURL{
				Type:       "rpm",
				Namespace:  "fedora",
				Name:       "curl",
				Version:    "7.50.3-1.fc25",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"arch": "i386", "distro": "fedora-25", "sourcerpm": "curl-7.50.3-1.fc25.src.rpm"}),
			},
		}, {
			name: "cos",
			purl: "pkg:cos/python-exec@17162.336.16?distro=cos-101",
			want: purl.PackageURL{
				Type:       purl.TypeCOS,
				Name:       "python-exec",
				Version:    "17162.336.16",
				Qualifiers: purl.QualifiersFromMap(map[string]string{"distro": "cos-101"}),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := purl.FromString(test.purl)
			if err != nil {
				t.Fatalf("FromString(%+v) error: %v", test.purl, err)
			}
			if diff := cmp.Diff(test.want.String(), got.String()); diff != "" {
				t.Fatalf("FromString(%+v) returned unexpected result; diff (-want +got):\n%s", test.purl, diff)
			}
		})
	}
}

func TestFromStringInvalidPURL(t *testing.T) {
	tests := []struct {
		name string
		purl string
	}{
		{
			name: "missing type",
			purl: "pkg:/package-name@1.2.3",
		}, {
			name: "invalid type",
			purl: "pkg:unknown/package-name@1.2.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := purl.FromString(test.purl); err == nil {
				t.Fatalf("FromString(%+v) got no error, expected one", test.purl)
			}
		})
	}
}

func TestQualifiersFromMap(t *testing.T) {
	tests := []struct {
		name           string
		qualifierMap   map[string]string
		wantQualifiers purl.Qualifiers
	}{
		{
			name: "normal transcription",
			qualifierMap: map[string]string{
				"qual":  "ifier",
				"other": "qualifier",
			},
			wantQualifiers: []packageurl.Qualifier{
				{Key: "other", Value: "qualifier"},
				{Key: "qual", Value: "ifier"},
			},
		}, {
			name: "filters only empty value",
			qualifierMap: map[string]string{
				"empty": "",
				"other": "qualifier",
			},
			wantQualifiers: []packageurl.Qualifier{
				{Key: "other", Value: "qualifier"},
			},
		}, {
			name: "empty qualifiers if all empty",
			qualifierMap: map[string]string{
				"empty": "",
			},
			wantQualifiers: []packageurl.Qualifier{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := purl.QualifiersFromMap(test.qualifierMap)

			if diff := cmp.Diff(test.wantQualifiers, got); diff != "" {
				t.Fatalf("QualifiersFromMap(%+v) returned unexpected result; diff (-want +got):\n%s", test.qualifierMap, diff)
			}
		})
	}
}
