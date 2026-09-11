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

package osvutil_test

import (
	"testing"

	"github.com/google/osv-scalibr/enricher/vulnmatch/internal/osvutil"
	"github.com/google/osv-scalibr/extractor"
	archivemetadata "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	apkmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
)

func TestParsePackage(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want osvutil.NormalizedPackage
	}{
		{
			name: "Standard PyPI Ecosystem",
			pkg: &extractor.Package{
				PURLType: purl.TypePyPi,
				Name:     "django",
				Version:  "1.20",
			},
			want: osvutil.NormalizedPackage{
				Name:      "django",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemPyPI),
				Version:   "1.20",
			},
		},
		{
			name: "Fallback to GIT if empty and SourceCode Repo set",
			pkg: &extractor.Package{
				Name:       "my-pkg",
				Version:    "1.0",
				SourceCode: &extractor.SourceCodeIdentifier{Repo: "https://github.com/foo/bar", Commit: "abcdef"},
			},
			want: osvutil.NormalizedPackage{
				Name:      "https://github.com/foo/bar",
				Ecosystem: osvecosystem.MustParse("GIT"),
				Version:   "1.0",
				Commit:    "abcdef",
			},
		},
		{
			name: "PyPI Name Normalization",
			pkg: &extractor.Package{
				PURLType: purl.TypePyPi,
				Name:     "Django_Dev.pkg",
				Version:  "1.20",
			},
			want: osvutil.NormalizedPackage{
				Name:      "django-dev-pkg",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemPyPI),
				Version:   "1.20",
			},
		},
		{
			name: "Go stdlib patch",
			pkg: &extractor.Package{
				PURLType: purl.TypeGolang,
				Name:     "go",
				Version:  "1.20",
			},
			want: osvutil.NormalizedPackage{
				Name:      "stdlib",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemGo),
				Version:   "1.20",
			},
		},
		{
			name: "Maven archive group:artifact",
			pkg: &extractor.Package{
				PURLType: purl.TypeMaven,
				Name:     "some-name",
				Version:  "1.0",
				Metadata: &archivemetadata.Metadata{
					GroupID:    "com.google",
					ArtifactID: "guava",
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "com.google:guava",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemMaven),
				Version:   "1.0",
			},
		},
		{
			name: "Debian source name fallback",
			pkg: &extractor.Package{
				PURLType: purl.TypeDebian,
				Name:     "binary-name",
				Version:  "1.0",
				Metadata: &dpkgmetadata.Metadata{
					SourceName: "source-name",
					OSID:       "debian",
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "source-name",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemDebian),
				Version:   "1.0",
			},
		},
		{
			name: "Apk origin name fallback",
			pkg: &extractor.Package{
				PURLType: purl.TypeApk,
				Name:     "binary-name",
				Version:  "1.0",
				Metadata: &apkmetadata.Metadata{
					OriginName: "origin-name",
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "origin-name",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemAlpine),
				Version:   "1.0",
			},
		},
		{
			name: "Go major version suffix patch",
			pkg: &extractor.Package{
				PURLType: purl.TypeGolang,
				Name:     "github.com/go-jose/go-jose",
				Version:  "4.1.3",
			},
			want: osvutil.NormalizedPackage{
				Name:      "github.com/go-jose/go-jose/v4",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemGo),
				Version:   "4.1.3",
			},
		},
		{
			name: "Homebrew repo fallback (always lowercase)",
			pkg: &extractor.Package{
				PURLType:   purl.TypeBrew,
				Name:       "homebrew-pkg",
				Version:    "1.0",
				SourceCode: &extractor.SourceCodeIdentifier{Repo: "Foo/Bar"},
			},
			want: osvutil.NormalizedPackage{
				Name:      "foo/bar",
				Ecosystem: osvecosystem.MustParse("GIT"),
				Version:   "1.0",
			},
		},
		{
			name: "GIT repo (normalize only github/gitlab)",
			pkg: &extractor.Package{
				PURLType:   "git",
				Name:       "git-pkg",
				Version:    "1.0",
				SourceCode: &extractor.SourceCodeIdentifier{Repo: "github.com/Foo/Bar"},
			},
			want: osvutil.NormalizedPackage{
				Name:      "github.com/foo/bar",
				Ecosystem: osvecosystem.MustParse("GIT"),
				Version:   "1.0",
			},
		},
		{
			name: "GIT repo (do not normalize other hosts)",
			pkg: &extractor.Package{
				PURLType:   "git",
				Name:       "git-pkg",
				Version:    "1.0",
				SourceCode: &extractor.SourceCodeIdentifier{Repo: "example.com/Foo/Bar"},
			},
			want: osvutil.NormalizedPackage{
				Name:      "example.com/Foo/Bar",
				Ecosystem: osvecosystem.MustParse("GIT"),
				Version:   "1.0",
			},
		},
		{
			name: "RPM with epoch (Red Hat)",
			pkg: &extractor.Package{
				PURLType: purl.TypeRPM,
				Name:     "bash",
				Version:  "5.1-6",
				Metadata: &rpmmetadata.Metadata{
					OSID:      "rhel",
					OSCPEName: "cpe:/o:redhat:enterprise_linux:9::baseos",
					Epoch:     1,
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "bash",
				Ecosystem: osvecosystem.Parsed{Ecosystem: "Red Hat", Suffix: "enterprise_linux:9::baseos"},
				Version:   "1:5.1-6",
			},
		},
		{
			name: "RPM without epoch (Red Hat)",
			pkg: &extractor.Package{
				PURLType: purl.TypeRPM,
				Name:     "bash",
				Version:  "5.1-6",
				Metadata: &rpmmetadata.Metadata{
					OSID:      "rhel",
					OSCPEName: "cpe:/o:redhat:enterprise_linux:9::baseos",
					Epoch:     0,
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "bash",
				Ecosystem: osvecosystem.Parsed{Ecosystem: "Red Hat", Suffix: "enterprise_linux:9::baseos"},
				Version:   "5.1-6",
			},
		},
		{
			name: "RPM with epoch (openEuler - non-epoch ecosystem)",
			pkg: &extractor.Package{
				PURLType: purl.TypeRPM,
				Name:     "bash",
				Version:  "5.1-6",
				Metadata: &rpmmetadata.Metadata{
					OSID:  "openEuler",
					Epoch: 1,
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "bash",
				Ecosystem: osvecosystem.Parsed{Ecosystem: "openEuler", Suffix: ""},
				Version:   "5.1-6",
			},
		},
		{
			name: "RubyGems plain gem version",
			pkg: &extractor.Package{
				PURLType: purl.TypeGem,
				Name:     "nokogiri",
				Version:  "1.19.3",
			},
			want: osvutil.NormalizedPackage{
				Name:      "nokogiri",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemRubyGems),
				Version:   "1.19.3",
			},
		},
		{
			name: "RubyGems platform-specific gem version",
			pkg: &extractor.Package{
				PURLType: purl.TypeGem,
				Name:     "nokogiri",
				Version:  "1.19.3-x86_64-linux-gnu",
			},
			want: osvutil.NormalizedPackage{
				Name:      "nokogiri",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemRubyGems),
				Version:   "1.19.3",
			},
		},
		{
			name: "RubyGems malformed leading-hyphen version is left untouched",
			pkg: &extractor.Package{
				PURLType: purl.TypeGem,
				Name:     "example",
				Version:  "-x86_64-linux-gnu",
			},
			want: osvutil.NormalizedPackage{
				Name:      "example",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemRubyGems),
				Version:   "-x86_64-linux-gnu",
			},
		},
		{
			name: "RubyGems malformed trailing-hyphen version is left untouched",
			pkg: &extractor.Package{
				PURLType: purl.TypeGem,
				Name:     "example",
				Version:  "1.0.0-",
			},
			want: osvutil.NormalizedPackage{
				Name:      "example",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemRubyGems),
				Version:   "1.0.0-",
			},
		},
		{
			name: "npm scoped package PURL namespace",
			pkg: &extractor.Package{
				PURLType: purl.TypeNPM,
				Name:     "client-lambda",
				Version:  "3.1037.0",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:npm/%40aws-sdk/client-lambda@3.1037.0"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "@aws-sdk/client-lambda",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemNPM),
				Version:   "3.1037.0",
			},
		},
		{
			name: "Maven group:artifact PURL namespace",
			pkg: &extractor.Package{
				PURLType: purl.TypeMaven,
				Name:     "commons-lang3",
				Version:  "3.12.0",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "org.apache.commons:commons-lang3",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemMaven),
				Version:   "3.12.0",
			},
		},
		{
			name: "Golang import path PURL namespace",
			pkg: &extractor.Package{
				PURLType: purl.TypeGolang,
				Name:     "gin",
				Version:  "1.9.1",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "github.com/gin-gonic/gin",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemGo),
				Version:   "1.9.1",
			},
		},
		{
			name: "Golang package name ending in '/go' with PURL namespace should not be patched to stdlib",
			pkg: &extractor.Package{
				PURLType: purl.TypeGolang,
				Name:     "go",
				Version:  "1.1.12",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:golang/github.com/json-iterator/go@v1.1.12"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "github.com/json-iterator/go",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemGo),
				Version:   "1.1.12",
			},
		},
		{
			name: "Debian distro PURL namespace ignored for name",
			pkg: &extractor.Package{
				PURLType: purl.TypeDebian,
				Name:     "bash",
				Version:  "5.1-2",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:deb/debian/bash@5.1-2?distro=debian-11"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "bash",
				Ecosystem: osvecosystem.Parsed{Ecosystem: osvconstants.EcosystemDebian, Suffix: "11"},
				Version:   "5.1-2",
			},
		},
		{
			name: "Already-namespaced npm package (no duplicate prefix)",
			pkg: &extractor.Package{
				PURLType: purl.TypeNPM,
				Name:     "@aws-sdk/client-lambda",
				Version:  "3.1037.0",
				Metadata: &cdxmeta.Metadata{
					PURL: purlFromString(t, "pkg:npm/%40aws-sdk/client-lambda@3.1037.0"),
				},
			},
			want: osvutil.NormalizedPackage{
				Name:      "@aws-sdk/client-lambda",
				Ecosystem: osvecosystem.FromEcosystem(osvconstants.EcosystemNPM),
				Version:   "3.1037.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "Go major version suffix patch" {
				purlVal, _ := purl.FromString("pkg:golang/github.com/go-jose/go-jose@v4.1.3#v4")
				tc.pkg.Metadata = &cdxmeta.Metadata{
					PURL: &purlVal,
				}
			}

			got := osvutil.ParsePackage(tc.pkg)
			if got.Name != tc.want.Name {
				t.Errorf("ParsePackage().Name = %q, want %q", got.Name, tc.want.Name)
			}
			if got.Ecosystem != tc.want.Ecosystem {
				t.Errorf("ParsePackage().Ecosystem = %v, want %v", got.Ecosystem, tc.want.Ecosystem)
			}
			if got.Version != tc.want.Version {
				t.Errorf("ParsePackage().Version = %q, want %q", got.Version, tc.want.Version)
			}
			if got.Commit != tc.want.Commit {
				t.Errorf("ParsePackage().Commit = %q, want %q", got.Commit, tc.want.Commit)
			}
		})
	}
}

func purlFromString(t *testing.T, s string) *purl.PackageURL {
	t.Helper()
	p, err := purl.FromString(s)
	if err != nil {
		t.Fatalf("purl.FromString(%q) failed: %v", s, err)
	}
	return &p
}
