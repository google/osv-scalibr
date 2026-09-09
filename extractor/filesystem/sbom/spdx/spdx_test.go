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

package spdx_test

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = spdx.Extractor{}

	tests := []struct {
		name           string
		path           string
		wantIsRequired bool
	}{
		{
			name:           "sbom.spdx",
			path:           "testdata/sbom.spdx",
			wantIsRequired: true,
		},
		{
			name:           "sbom.SPDX",
			path:           "testdata/sbom.SPDX",
			wantIsRequired: true,
		},
		{
			name:           "sbom.SpDx",
			path:           "testdata/sbom.SpDx",
			wantIsRequired: true,
		},
		{
			name:           "sbom.spdx.json",
			path:           "testdata/sbom.spdx.json",
			wantIsRequired: true,
		},
		{
			name:           ".sbom.spdx.json",
			path:           "testdata/.sbom.spdx.json",
			wantIsRequired: true,
		},
		{
			name:           ".spdx.sbom.json",
			path:           "testdata/.spdx.sbom.json",
			wantIsRequired: true,
		},
		{
			name:           "sbom.spdx.yml",
			path:           "testdata/sbom.spdx.yml",
			wantIsRequired: true,
		},
		{
			name:           "sbom.spdx.rdf",
			path:           "testdata/sbom.spdx.rdf",
			wantIsRequired: true,
		},
		{
			name:           "sbom.spdx.rdf.xml",
			path:           "testdata/sbom.spdx.rdf.xml",
			wantIsRequired: true,
		},
		{
			name:           "random_file.ext",
			path:           "testdata/random_file.ext",
			wantIsRequired: false,
		},
		{
			name:           "sbom.spdx.foo.ext",
			path:           "testdata/sbom.spdx.foo.ext",
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
	var e filesystem.Extractor = spdx.Extractor{}

	tests := []struct {
		name         string
		path         string
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			name:         "minimal.spdx.json",
			path:         "testdata/minimal.spdx.json",
			wantPackages: []*extractor.Package{},
		},
		{
			name: "sbom.spdx.json",
			path: "testdata/sbom.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name: "cpe:2.3:a:nginx:nginx:1.21.1",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "nginx",
						CPEs:   []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:nginx:nginx:1.21.1",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.json"),
				},
				{
					Name:     "openssl",
					Version:  "1.1.1l",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "openssl",
						PURL:   getPURL("openssl", "1.1.1l"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "purl",
								Locator:  "pkg:generic/openssl@1.1.1l",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.json"),
				},
			},
		},
		{
			name: "purl_and_cpe.spdx.json",
			path: "testdata/purl_and_cpe.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "nginx",
					Version:  "1.21.1",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "nginx",
						CPEs:   []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
						PURL:   getPURL("nginx", "1.21.1"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:nginx:nginx:1.21.1",
							},
							{
								Category: "SECURITY",
								RefType:  "purl",
								Locator:  "pkg:generic/nginx@1.21.1",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/purl_and_cpe.spdx.json"),
				},
				{
					Name:     "openssl",
					Version:  "1.1.1l",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "openssl",
						PURL:   getPURL("openssl", "1.1.1l"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "purl",
								Locator:  "pkg:generic/openssl@1.1.1l",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/purl_and_cpe.spdx.json"),
				},
			},
		},
		{
			name: "sbom.spdx",
			path: "testdata/sbom.spdx",
			wantPackages: []*extractor.Package{
				{
					Name: "cpe:2.3:a:nginx:nginx:1.21.1",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "nginx",
						CPEs:   []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:nginx:nginx:1.21.1",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx"),
				},
				{
					Name:     "openssl",
					Version:  "1.1.1l",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "openssl",
						PURL:   getPURL("openssl", "1.1.1l"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "purl",
								Locator:  "pkg:generic/openssl@1.1.1l",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx"),
				},
			},
		},
		{
			name: "sbom.spdx.yml",
			path: "testdata/sbom.spdx.yml",
			wantPackages: []*extractor.Package{
				{
					Name: "cpe:2.3:a:nginx:nginx:1.21.1",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "nginx",
						CPEs:   []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:nginx:nginx:1.21.1",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.yml"),
				},
				{
					Name:     "openssl",
					Version:  "1.1.1l",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "openssl",
						PURL:   getPURL("openssl", "1.1.1l"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "purl",
								Locator:  "pkg:generic/openssl@1.1.1l",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.yml"),
				},
			},
		},
		{
			name: "sbom.spdx.rdf",
			path: "testdata/sbom.spdx.rdf",
			wantPackages: []*extractor.Package{
				{
					Name: "cpe:2.3:a:nginx:nginx:1.21.1",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "nginx",
						CPEs:   []string{"cpe:2.3:a:nginx:nginx:1.21.1"},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "http://spdx.org/rdf/references/cpe23Type",
								Locator:  "cpe:2.3:a:nginx:nginx:1.21.1",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.rdf"),
				},
				{
					Name:     "openssl",
					Version:  "1.1.1l",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "openssl",
						PURL:   getPURL("openssl", "1.1.1l"),
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "SECURITY",
								RefType:  "http://spdx.org/rdf/references/purl",
								Locator:  "pkg:generic/openssl@1.1.1l",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/sbom.spdx.rdf"),
				},
			},
		},
		{
			name: "dhi/.spdx.dhi-pkg-python.json",
			path: "testdata/dhi/.spdx.dhi-pkg-python.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "pkg-python",
					Version:  "3.14.3-debian13",
					PURLType: purl.TypeDocker,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "dhi-pkg-python",
						PURL: &purl.PackageURL{
							Type:      purl.TypeDocker,
							Namespace: "dhi",
							Name:      "pkg-python",
							Version:   "3.14.3-debian13",
							Qualifiers: purl.QualifiersFromMap(map[string]string{
								"platform":   "linux/amd64",
								"os_name":    "debian",
								"os_version": "13",
							}),
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:docker/dhi/pkg-python@3.14.3-debian13?platform=linux%2Famd64&os_name=debian&os_version=13",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/dhi/.spdx.dhi-pkg-python.json"),
				},
			},
		},
		{
			name: "dhi/.spdx.dhi-python.json",
			path: "testdata/dhi/.spdx.dhi-python.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "python",
					Version:  "3.14.3-debian13-dev",
					PURLType: purl.TypeDocker,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "dhi-python",
						PURL: &purl.PackageURL{
							Type:      purl.TypeDocker,
							Namespace: "dhi",
							Name:      "python",
							Version:   "3.14.3-debian13-dev",
							Qualifiers: purl.QualifiersFromMap(map[string]string{
								"platform":   "linux/amd64",
								"os_name":    "debian",
								"os_version": "13",
							}),
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:docker/dhi/python@3.14.3-debian13-dev?platform=linux%2Famd64&os_name=debian&os_version=13",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/dhi/.spdx.dhi-python.json"),
				},
			},
		},
		{
			name: "dhi/.spdx.python.json",
			path: "testdata/dhi/.spdx.python.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "python",
					Version:  "3.14.3",
					PURLType: purl.TypeDHI,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "python",
						PURL: &purl.PackageURL{
							Type:       purl.TypeDHI,
							Name:       "python",
							Version:    "3.14.3",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:dhi/python@3.14.3",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/dhi/.spdx.python.json"),
				},
			},
		},
		{
			name: "external_refs.spdx.json",
			path: "testdata/external_refs.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name: "flatbuffers",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "Package-flatbuffers",
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "OTHER",
								RefType:  "SourceURI",
								Locator:  "third_party/flatbuffers",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/external_refs.spdx.json"),
				},
				{
					Name:     "flatbuffers",
					Version:  "25.9.23",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-flatbuffers",
						CPEs:   []string{"cpe:2.3:a:some_company:flatbuffers:25.9.23:*:*:*:*:*:*:*"},
						PURL: &purl.PackageURL{
							Type:       purl.TypeGeneric,
							Namespace:  "some_company",
							Name:       "flatbuffers",
							Version:    "25.9.23",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/some_company/flatbuffers@25.9.23",
							},
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:some_company:flatbuffers:25.9.23:*:*:*:*:*:*:*",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/external_refs.spdx.json"),
				},
				{
					Name:    "custom-pkg",
					Version: "1.0.0",
					Metadata: &spdxmeta.Metadata{
						SPDXID: "custom-pkg",
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "OTHER",
								RefType:  "vcs",
								Locator:  "git+https://example.com/repo@v1.0.0",
								Comment:  "source code repo",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/external_refs.spdx.json"),
				},
			},
		},
		{
			name: "descendant_of.spdx.json",
			path: "testdata/descendant_of.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "log4j",
					Version:  "1.2.15",
					PURLType: purl.TypeMaven,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-log4j",
						CPEs:   []string{"cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*"},
						PURL: &purl.PackageURL{
							Type:       purl.TypeMaven,
							Namespace:  "log4j",
							Name:       "log4j",
							Version:    "1.2.15",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:maven/log4j/log4j@1.2.15",
							},
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*",
							},
							{
								Category: "OTHER",
								RefType:  "DownstreamSourceURI",
								Locator:  "path/to/log4j/v1_2_15",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/descendant_of.spdx.json"),
				},
			},
		},
		{
			name: "ancestor_of.spdx.json",
			path: "testdata/ancestor_of.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "log4j",
					Version:  "1.2.15",
					PURLType: purl.TypeMaven,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-log4j",
						CPEs:   []string{"cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*"},
						PURL: &purl.PackageURL{
							Type:       purl.TypeMaven,
							Namespace:  "log4j",
							Name:       "log4j",
							Version:    "1.2.15",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:maven/log4j/log4j@1.2.15",
							},
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*",
							},
							{
								Category: "OTHER",
								RefType:  "DownstreamSourceURI",
								Locator:  "path/to/log4j/v1_2_15",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/ancestor_of.spdx.json"),
				},
			},
		},
		{
			name: "multi_descendant.spdx.json",
			path: "testdata/multi_descendant.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "pkg",
					Version:  "5.0",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-pkg",
						PURL: &purl.PackageURL{
							Type:       purl.TypeGeneric,
							Namespace:  "google",
							Name:       "pkg",
							Version:    "5.0",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/google/pkg@5.0",
							},
							{
								Category: "OTHER",
								RefType:  "DownstreamSourceURI",
								Locator:  "some/downstream/location",
							},
							{
								Category: "OTHER",
								RefType:  "DownstreamSourceURI",
								Locator:  "another/downstream/location",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/multi_descendant.spdx.json"),
				},
			},
		},
		{
			name: "independent_packages_descendant.spdx.json",
			path: "testdata/independent_packages_descendant.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "child",
					Version:  "1.0.0",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-Child",
						PURL: &purl.PackageURL{
							Type:       purl.TypeGeneric,
							Name:       "child",
							Version:    "1.0.0",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/child@1.0.0",
							},
							{
								Category: "OTHER",
								RefType:  "ExtraChildRef",
								Locator:  "child-ref-value",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/independent_packages_descendant.spdx.json"),
				},
				{
					Name:     "parent",
					Version:  "2.0.0",
					PURLType: purl.TypeGeneric,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-Parent",
						PURL: &purl.PackageURL{
							Type:       purl.TypeGeneric,
							Name:       "parent",
							Version:    "2.0.0",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/parent@2.0.0",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/independent_packages_descendant.spdx.json"),
				},
			},
		},
		{
			name: "overlapping_refs.spdx.json",
			path: "testdata/overlapping_refs.spdx.json",
			wantPackages: []*extractor.Package{
				{
					Name:     "log4j",
					Version:  "1.2.15",
					PURLType: purl.TypeMaven,
					Metadata: &spdxmeta.Metadata{
						SPDXID: "SourcePackage-log4j",
						CPEs:   []string{"cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*"},
						PURL: &purl.PackageURL{
							Type:       purl.TypeMaven,
							Namespace:  "log4j",
							Name:       "log4j",
							Version:    "1.2.15",
							Qualifiers: purl.Qualifiers{},
						},
						ExternalReferences: []spdxmeta.ExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:maven/log4j/log4j@1.2.15",
							},
							{
								Category: "SECURITY",
								RefType:  "cpe23Type",
								Locator:  "cpe:2.3:a:apache:log4j:1.2.15:*:*:*:*:*:*:*",
							},
							{
								Category: "OTHER",
								RefType:  "DownstreamSourceURI",
								Locator:  "path/to/log4j/v1_2_15",
							},
						},
					},
					Location: extractor.LocationFromPath("testdata/overlapping_refs.spdx.json"),
				},
			},
		},
		{
			name:    "invalid_sbom.spdx",
			path:    "testdata/invalid_sbom.spdx",
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "sbom.spdx.foo.ext",
			path:    "testdata/sbom.spdx.foo.ext",
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		// Note the subtest here
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

			if diff := cmp.Diff(want, got, cmpopts.SortSlices(pkgCompare)); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

// pkgCompare is a custom comparison function for extractor.Package.
// It sorts packages by name, then version, then PURL type.
func pkgCompare(i1, i2 *extractor.Package) bool {
	if i1.Name != i2.Name {
		return i1.Name < i2.Name
	}
	if i1.Version != i2.Version {
		return i1.Version < i2.Version
	}
	return i1.PURLType < i2.PURLType
}

func getPURL(name, version string) *purl.PackageURL {
	return &purl.PackageURL{
		Type:       purl.TypeGeneric,
		Name:       name,
		Version:    version,
		Qualifiers: purl.Qualifiers{},
	}
}
