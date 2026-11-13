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

package converter_test

import (
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	structpb "google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestToCDX(t *testing.T) {
	// Make UUIDs deterministic
	uuid.SetRand(rand.New(rand.NewSource(1)))
	defaultBOM := cyclonedx.NewBOM()

	testCases := []struct {
		desc   string
		inv    inventory.Inventory
		config converter.CDXConfig
		want   *cyclonedx.BOM
	}{
		{
			desc: "Package_with_custom_config",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
			},
			config: converter.CDXConfig{
				ComponentName:    "sbom-1",
				ComponentVersion: "1.0.0",
				Authors:          []string{"author"},
			},
			want: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						Name:    "sbom-1",
						Version: "1.0.0",
						BOMRef:  "52fdfc07-2182-454f-963f-5f0f9a621d72",
					},
					Authors: new([]cyclonedx.OrganizationalContact{{Name: "author"}}),
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: new([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: new([]cyclonedx.Component{
					{
						BOMRef:     "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
						Type:       "library",
						Name:       "software",
						Version:    "1.2.3",
						PackageURL: "pkg:pypi/software@1.2.3",
					},
				}),
			},
		},
		{
			desc: "Package_with_custom_config_and_cdx-component-type",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
			},
			config: converter.CDXConfig{
				ComponentName:    "sbom-2",
				ComponentType:    "library",
				ComponentVersion: "1.0.0",
				Authors:          []string{"author"},
			},
			want: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						Name:    "sbom-2",
						Type:    cyclonedx.ComponentTypeLibrary,
						Version: "1.0.0",
						BOMRef:  "81855ad8-681d-4d86-91e9-1e00167939cb",
					},
					Authors: new([]cyclonedx.OrganizationalContact{{Name: "author"}}),
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: new([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: new([]cyclonedx.Component{
					{
						BOMRef:     "6694d2c4-22ac-4208-a007-2939487f6999",
						Type:       "library",
						Name:       "software",
						Version:    "1.2.3",
						PackageURL: "pkg:pypi/software@1.2.3",
					},
				}),
			},
		},
		{
			desc: "Packages_with_licenses",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "no-licenses",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
					},
					{
						Name:     "single-license",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
						Licenses: []string{"MIT"},
					},
					{
						Name:     "license-expression",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
						Licenses: []string{"MIT AND Zlib"},
					},
					{
						Name:     "multiple-licenses",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
						Licenses: []string{"MIT", "Apache-2.0"},
					},
					{
						Name:     "custom-license",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
						Licenses: []string{"MIT", "My Custom License"},
					},
					{
						Name:     "non-standard-license",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
						Licenses: []string{"non-standard", "Apache-2.0"},
					},
				},
			},
			want: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "eb9d18a4-4784-445d-87f3-c67cf22746e9",
					},
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: new([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: new([]cyclonedx.Component{
					{
						BOMRef:     "95af5a25-3679-41ba-a2ff-6cd471c483f1",
						Type:       "library",
						Name:       "no-licenses",
						Version:    "1.0.0",
						PackageURL: "pkg:npm/no-licenses@1.0.0",
					},
					{
						BOMRef:     "5fb90bad-b37c-4821-b6d9-5526a41a9504",
						Type:       "library",
						Name:       "single-license",
						Version:    "1.0.0",
						Licenses:   &cyclonedx.Licenses{{Expression: "MIT"}},
						PackageURL: "pkg:npm/single-license@1.0.0",
					},
					{
						BOMRef:     "680b4e7c-8b76-4a1b-9d49-d4955c848621",
						Type:       "library",
						Name:       "license-expression",
						Version:    "1.0.0",
						Licenses:   &cyclonedx.Licenses{{Expression: "MIT AND Zlib"}},
						PackageURL: "pkg:npm/license-expression@1.0.0",
					},
					{
						BOMRef:     "6325253f-ec73-4dd7-a9e2-8bf921119c16",
						Type:       "library",
						Name:       "multiple-licenses",
						Version:    "1.0.0",
						Licenses:   &cyclonedx.Licenses{{Expression: "Apache-2.0 AND MIT"}},
						PackageURL: "pkg:npm/multiple-licenses@1.0.0",
					},
					{
						BOMRef:     "0f070244-8615-4bda-8831-3f6a8eb668d2",
						Type:       "library",
						Name:       "custom-license",
						Version:    "1.0.0",
						Licenses:   &cyclonedx.Licenses{{Expression: "LicenseRef-My-Custom-License AND MIT"}},
						PackageURL: "pkg:npm/custom-license@1.0.0",
					},
					{
						BOMRef:  "0bf50598-7592-4e66-8a5b-df2c7fc48445",
						Type:    "library",
						Name:    "non-standard-license",
						Version: "1.0.0",
						Licenses: &cyclonedx.Licenses{
							{License: &cyclonedx.License{Name: "non-standard"}},
							{License: &cyclonedx.License{ID: "Apache-2.0"}},
						},
						PackageURL: "pkg:npm/non-standard-license@1.0.0",
					},
				}),
			},
		},
		{
			desc: "Packages_with_deprecation",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "not-deprecated",
						Version:  "1.0.0",
						PURLType: purl.TypeNPM,
					},
					{
						Name:       "deprecated",
						Version:    "1.0.0",
						PURLType:   purl.TypeNPM,
						Deprecated: true,
					},
				},
			},
			want: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						BOMRef: "92d2572b-cd06-48d2-96c5-2f5054e2d083",
					},
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: new([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: new([]cyclonedx.Component{
					{
						BOMRef:     "6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						Type:       "library",
						Name:       "not-deprecated",
						Version:    "1.0.0",
						PackageURL: "pkg:npm/not-deprecated@1.0.0",
					},
					{
						BOMRef:     "172ed857-94bb-458b-8c3b-525da1786f9f",
						Type:       "library",
						Name:       "deprecated",
						Version:    "1.0.0",
						PackageURL: "pkg:npm/deprecated@1.0.0",
						Properties: &[]cyclonedx.Property{{Name: "osv:deprecated", Value: "true"}},
					},
				}),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToCDX(tc.inv, tc.config)
			// Can't mock time.Now() so skip verifying the timestamp.
			tc.want.Metadata.Timestamp = got.Metadata.Timestamp
			// Auto-populated fields
			tc.want.XMLNS = defaultBOM.XMLNS
			tc.want.JSONSchema = defaultBOM.JSONSchema
			tc.want.BOMFormat = defaultBOM.BOMFormat
			tc.want.SpecVersion = defaultBOM.SpecVersion
			tc.want.Version = defaultBOM.Version

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("converter.ToCDX(%v): unexpected diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}

func TestToCDX_Vulnerabilities_Affects(t *testing.T) {
	type vulnAffects struct {
		ID      string
		Affects []string
	}

	// two occurrences of the same package, which should be referenced separately
	pkgA := &extractor.Package{Name: "lodash", Version: "4.17.20", PURLType: purl.TypeNPM}
	pkgB := &extractor.Package{Name: "lodash", Version: "4.17.20", PURLType: purl.TypeNPM}
	pkgC := &extractor.Package{Name: "other", Version: "1.0.0", PURLType: purl.TypeNPM}

	// not part of the inventory packages
	pkgD := &extractor.Package{Name: "missing", Version: "1.0.0", PURLType: purl.TypeNPM}

	tests := []struct {
		name  string
		vulns []*inventory.PackageVuln
		// affected components are given as indexes into the inventory packages (pkgA, pkgB, pkgC)
		want []vulnAffects
	}{
		{
			name:  "no_vulnerabilities",
			vulns: nil,
			want:  nil,
		},
		{
			name: "one_vulnerability_one_package",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgA},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"0"}},
			},
		},
		{
			name: "same_vulnerability_multiple_packages",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgA},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgC},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"0", "2"}},
			},
		},
		{
			name: "same_package_different_occurrences",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgA},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-2"}, Package: pkgB},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"0"}},
				{ID: "GHSA-2", Affects: []string{"1"}},
			},
		},
		{
			name: "unordered_vulnerabilities",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-3"}, Package: pkgA},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgB},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-2"}, Package: pkgC},
			},
			// vulns should be sorted by id
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"1"}},
				{ID: "GHSA-2", Affects: []string{"2"}},
				{ID: "GHSA-3", Affects: []string{"0"}},
			},
		},
		{
			name: "same_package_listed_twice_for_same_vulnerability",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgA},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgA},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"0"}},
			},
		},
		{
			name: "package_not_in_inventory",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgD},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-2"}, Package: pkgD},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-2"}, Package: pkgA},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{}},
				{ID: "GHSA-2", Affects: []string{"0"}},
			},
		},
		{
			name: "mixed_packages_and_vulnerabilities",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgB},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}, Package: pkgC},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-2"}, Package: pkgB},
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-3"}, Package: pkgA},
			},
			want: []vulnAffects{
				{ID: "GHSA-1", Affects: []string{"1", "2"}},
				{ID: "GHSA-2", Affects: []string{"1"}},
				{ID: "GHSA-3", Affects: []string{"0"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := inventory.Inventory{
				Packages:     []*extractor.Package{pkgA, pkgB, pkgC},
				PackageVulns: tt.vulns,
			}

			bom := converter.ToCDX(inv, converter.CDXConfig{})

			// map component refs back to their index, since the refs are random
			indexes := make(map[string]string)
			for i, comp := range *bom.Components {
				indexes[comp.BOMRef] = strconv.Itoa(i)
			}

			var got []vulnAffects
			if bom.Vulnerabilities != nil {
				for _, vuln := range *bom.Vulnerabilities {
					affects := []string{}
					for _, affect := range *vuln.Affects {
						index, ok := indexes[affect.Ref]
						if !ok {
							index = "unknown ref " + affect.Ref
						}
						affects = append(affects, index)
					}
					got = append(got, vulnAffects{ID: vuln.ID, Affects: affects})
				}
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("converter.ToCDX(%v): unexpected vulnerabilities diff (-want +got):\n%s", inv, diff)
			}
		})
	}
}

func TestToCDX_Vulnerabilities_Fields(t *testing.T) {
	tests := []struct {
		name  string
		vulns []*inventory.PackageVuln
		want  *[]cyclonedx.Vulnerability
	}{
		{
			name: "empty_vulnerability",
			vulns: []*inventory.PackageVuln{
				{Vulnerability: &osvpb.Vulnerability{Id: "GHSA-1"}},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef:  "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:      "GHSA-1",
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "basic_vulnerability",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:      "GHSA-1",
						Details: "This is an open source vulnerability!",
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef:  "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:      "GHSA-1",
					Affects: &[]cyclonedx.Affects{},
					Detail:  "This is an open source vulnerability!",
				},
			},
		},
		{
			name: "fulsome_vulnerability",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:        "GO-2022-1144",
						Modified:  &timestamppb.Timestamp{},
						Published: &timestamppb.Timestamp{},
						Withdrawn: &timestamppb.Timestamp{},
						Aliases:   []string{"CVE-2022-41717", "GHSA-xrjj-mj9h-534m"},
						Summary:   "Excessive memory growth in net/http and golang.org/x/net/http2",
						Details: "An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests.\n\n" +
							"HTTP/2 server connections contain a cache of HTTP header keys sent by the client. While the total " +
							"number of entries in this cache is capped, an attacker sending very large keys can cause the " +
							"server to allocate approximately 64 MiB per open connection.",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "Go", Name: "stdlib"},
							},
						},
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_REPORT, Url: "https://go.dev/issue/56350"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455717"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455635"},
							{
								Type: osvpb.Reference_WEB,
								Url:  "https://groups.google.com/g/golang-announce/c/L_3rmdT0BMU/m/yZDrXjIiBQAJ",
							},
						},
						Credits: []*osvpb.Credit{{Name: "Josselin Costanzi"}},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GO-2022-1144",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-2022-41717", Source: &cyclonedx.Source{}},
						{ID: "GHSA-xrjj-mj9h-534m", Source: &cyclonedx.Source{}},
					},
					Description: "Excessive memory growth in net/http and golang.org/x/net/http2",
					Detail: "An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests.\n\n" +
						"HTTP/2 server connections contain a cache of HTTP header keys sent by the client. While the total " +
						"number of entries in this cache is capped, an attacker sending very large keys can cause the " +
						"server to allocate approximately 64 MiB per open connection.",
					Affects:   &[]cyclonedx.Affects{},
					Published: "1970-01-01T00:00:00Z",
					Updated:   "1970-01-01T00:00:00Z",
					Rejected:  "1970-01-01T00:00:00Z",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							{Name: "Josselin Costanzi"},
						},
					},
				},
			},
		},
		{
			name: "withdrawn_vulnerability",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						SchemaVersion: "1.7.0",
						Id:            "GHSA-rv95-896h-c2vc",
						Modified:      timestamppb.New(time.Date(2025, 7, 21, 16, 57, 31, 0, time.UTC)),
						Published:     timestamppb.New(time.Date(2024, 3, 25, 19, 40, 26, 0, time.UTC)),
						Withdrawn:     timestamppb.New(time.Date(2025, 7, 22, 16, 57, 31, 0, time.UTC)),
						Summary:       "Express.js Open Redirect in malformed URLs",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "npm", Name: "express", Purl: "pkg:npm/express"},
								Ranges:  []*osvpb.Range{{Type: osvpb.Range_SEMVER, Events: []*osvpb.Event{{Introduced: "0"}, {Fixed: "4.19.2"}}}},
								DatabaseSpecific: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2024/03/GHSA-rv95-896h-c2vc/GHSA-rv95-896h-c2vc.json"}},
									},
								},
							},
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef:      "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:          "GHSA-rv95-896h-c2vc",
					Description: "Express.js Open Redirect in malformed URLs",
					Affects:     &[]cyclonedx.Affects{},
					Published:   "2024-03-25T19:40:26Z",
					Updated:     "2025-07-21T16:57:31Z",
					Rejected:    "2025-07-22T16:57:31Z",
				},
			},
		},
		{
			// in practice this shouldn't happen, but if it ever does
			// then we just use the details of the first version
			name: "repeated_vulnerability",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:        "GO-2022-1144",
						Modified:  &timestamppb.Timestamp{},
						Published: &timestamppb.Timestamp{},
						Withdrawn: &timestamppb.Timestamp{},
						Aliases:   []string{"CVE-2022-41717", "GHSA-xrjj-mj9h-534m"},
						Summary:   "Excessive memory growth in net/http",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "Go", Name: "stdlib"},
							},
						},
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_REPORT, Url: "https://go.dev/issue/56350"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455717"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455635"},
							{
								Type: osvpb.Reference_WEB,
								Url:  "https://groups.google.com/g/golang-announce/c/L_3rmdT0BMU/m/yZDrXjIiBQAJ",
							},
						},
						Credits: []*osvpb.Credit{{Name: "Josselin Costanzi"}},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:        "GO-2022-1144",
						Modified:  &timestamppb.Timestamp{},
						Published: &timestamppb.Timestamp{},
						Withdrawn: &timestamppb.Timestamp{},
						Aliases:   []string{"CVE-2022-41717", "GHSA-xrjj-mj9h-534m"},
						Summary:   "Excessive memory growth in net/http and golang.org/x/net/http2",
						Details: "An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests.\n\n" +
							"HTTP/2 server connections contain a cache of HTTP header keys sent by the client. While the total " +
							"number of entries in this cache is capped, an attacker sending very large keys can cause the " +
							"server to allocate approximately 64 MiB per open connection.",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "Go", Name: "stdlib"},
							},
						},
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_REPORT, Url: "https://go.dev/issue/56350"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455717"},
							{Type: osvpb.Reference_FIX, Url: "https://go.dev/cl/455635"},
							{
								Type: osvpb.Reference_WEB,
								Url:  "https://groups.google.com/g/golang-announce/c/L_3rmdT0BMU/m/yZDrXjIiBQAJ",
							},
						},
						Credits: []*osvpb.Credit{{Name: "Josselin Costanzi"}},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GO-2022-1144",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-2022-41717", Source: &cyclonedx.Source{}},
						{ID: "GHSA-xrjj-mj9h-534m", Source: &cyclonedx.Source{}},
					},
					Description: "Excessive memory growth in net/http",
					Detail:      "",
					Affects:     &[]cyclonedx.Affects{},
					Published:   "1970-01-01T00:00:00Z",
					Updated:     "1970-01-01T00:00:00Z",
					Rejected:    "1970-01-01T00:00:00Z",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							{Name: "Josselin Costanzi"},
						},
					},
				},
			},
		},
		{
			name: "various_vulnerabilities",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:      "CVE-2020-11978",
						Summary: "CVE-2020-11978",
						Details: "CVE-2020-11978",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Name: "apache-airflow"},
								Severity: []*osvpb.Severity{
									{
										Type:  osvpb.Severity_CVSS_V3,
										Score: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
									},
								},
								Ranges: []*osvpb.Range{{
									Type:   osvpb.Range_ECOSYSTEM,
									Events: []*osvpb.Event{{Introduced: "0"}, {Fixed: "1.10.11"}},
								}},
							},
						},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"extra": {Kind: &structpb.Value_StringValue{
									StringValue: fmt.Sprintf("%s %s %s", "unknown", "1.0.0", "")},
								},
							},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "VULN-001",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"}, // 6.6
							{Type: osvpb.Severity_CVSS_V2, Score: "AV:L/AC:L/Au:S/C:P/I:P/A:C"},                   // 5.7
						},
						Aliases: []string{"CVE-111", "OSV-2"},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:      "VULN-003",
						Aliases: []string{"CVE-111", "OSV-2"},
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{
									Ecosystem: "npm",
									Name:      "pkg",
								},
								Ranges: []*osvpb.Range{
									{
										Type: osvpb.Range_SEMVER,
										Events: []*osvpb.Event{
											{Introduced: "0"},
											{Fixed: "1.9.1"},
										},
									},
								},
								Severity: []*osvpb.Severity{
									{Type: osvpb.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H"}, // 9.9
								},
							},
							{
								Package: &osvpb.Package{
									Ecosystem: "npm",
									Name:      "pkg",
								},
								Ranges: []*osvpb.Range{
									{
										Type: osvpb.Range_SEMVER,
										Events: []*osvpb.Event{
											{Introduced: "2.0.0"},
											{Fixed: "2.9.9"},
										},
									},
								},
								Severity: []*osvpb.Severity{
									{Type: osvpb.Severity_CVSS_V4, Score: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H"}, // 7.0
								},
							},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id:      "CVE-2023-38408",
						Summary: "CVE-2023-38408",
						Details: "CVE-2023-38408",
						Affected: []*osvpb.Affected{{
							Package: &osvpb.Package{
								Name: "openssh",
							},
							Severity: []*osvpb.Severity{{
								Type:  osvpb.Severity_CVSS_V3,
								Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
							}},
							Ranges: []*osvpb.Range{{
								Type:   osvpb.Range_ECOSYSTEM,
								Events: []*osvpb.Event{{Introduced: "0"}, {Fixed: "9.3.p2"}},
							}},
						}},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						SchemaVersion: "1.7.0",
						Id:            "GHSA-2c4m-59x9-fr2g",
						Modified:      timestamppb.New(time.Date(2023, 11, 8, 4, 12, 18, 674169000, time.UTC)),
						Published:     timestamppb.New(time.Date(2023, 5, 12, 20, 19, 25, 0, time.UTC)),
						Aliases:       []string{"CVE-2023-29401", "GO-2023-1737"},
						Summary:       "Gin Web Framework does not properly sanitize filename parameter ...",
						Details:       "The filename parameter of the Context.FileAttachment function is ...",
						Severity:      []*osvpb.Severity{{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_ADVISORY, Url: "https://nvd.nist.gov/vuln/detail/CVE-2023-29401"},
							{Type: osvpb.Reference_WEB, Url: "https://github.com/gin-gonic/gin/issues/3555"},
							{Type: osvpb.Reference_WEB, Url: "https://github.com/gin-gonic/gin/pull/3556"},
							{Type: osvpb.Reference_PACKAGE, Url: "https://github.com/gin-gonic/gin"},
							{Type: osvpb.Reference_WEB, Url: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
							{Type: osvpb.Reference_WEB, Url: "https://pkg.go.dev/vuln/GO-2023-1737"},
						},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"cwe_ids": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{Values: []*structpb.Value{
									{Kind: &structpb.Value_StringValue{StringValue: "CWE-494"}},
								}}}},
								"github_reviewed":    {Kind: &structpb.Value_BoolValue{BoolValue: true}},
								"github_reviewed_at": {Kind: &structpb.Value_StringValue{StringValue: "2023-05-12T20:19:25Z"}},
								"nvd_published_at":   {Kind: &structpb.Value_StringValue{StringValue: "2023-06-08T21:15:16Z"}},
								"severity":           {Kind: &structpb.Value_StringValue{StringValue: "MODERATE"}},
							},
						},
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{
									Ecosystem: "Go",
									Name:      "gin",
									Purl:      "pkg:golang/github.com/gin-gonic/gin",
								},
								Ranges: []*osvpb.Range{
									{Type: osvpb.Range_SEMVER, Events: []*osvpb.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}}},
								},
								DatabaseSpecific: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"source": {Kind: &structpb.Value_StringValue{StringValue: "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed/2023/05/GHSA-2c4m-59x9-fr2g/GHSA-2c4m-59x9-fr2g.json"}},
									},
								},
							},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						SchemaVersion: "1.7.0",
						Id:            "GO-2023-1737",
						Aliases:       []string{"CVE-2023-29401", "GHSA-2c4m-59x9-fr2g"},
						Summary:       "Improper handling of filenames in Content-Disposition HTTP heade...",
						Details:       "The filename parameter of the Context.FileAttachment function is ...",
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"review_status": {Kind: &structpb.Value_StringValue{StringValue: "REVIEWED"}},
								"url":           {Kind: &structpb.Value_StringValue{StringValue: "https://pkg.go.dev/vuln/GO-2023-1737"}},
							},
						},
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{
									Ecosystem: "Go",
									Name:      "gin",
									Purl:      "pkg:golang/github.com/gin-gonic/gin",
								},
								Ranges: []*osvpb.Range{
									{Type: osvpb.Range_SEMVER, Events: []*osvpb.Event{{Introduced: "1.3.1-0.20190301021747-ccb9e902956d"}, {Fixed: "1.9.1"}}},
								},
								DatabaseSpecific: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"source": {Kind: &structpb.Value_StringValue{StringValue: "https://vuln.go.dev/ID/GO-2023-1737.json"}},
									},
								},
								EcosystemSpecific: &structpb.Struct{
									Fields: map[string]*structpb.Value{
										"imports": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
											Values: []*structpb.Value{
												{Kind: &structpb.Value_StructValue{StructValue: &structpb.Struct{
													Fields: map[string]*structpb.Value{
														"path": {Kind: &structpb.Value_StringValue{StringValue: "github.com/gin-gonic/gin"}},
														"symbols": {Kind: &structpb.Value_ListValue{ListValue: &structpb.ListValue{
															Values: []*structpb.Value{
																{Kind: &structpb.Value_StringValue{StringValue: "Context.FileAttachment"}},
															},
														}}},
													},
												}}},
											},
										}}},
									},
								},
							},
						},
						Modified:  timestamppb.New(time.Date(2024, 5, 20, 16, 3, 47, 0, time.UTC)),
						Published: timestamppb.New(time.Date(2023, 5, 11, 18, 59, 56, 0, time.UTC)),
						Credits:   []*osvpb.Credit{{Name: "motoyasu-saburi"}},
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_REPORT, Url: "https://github.com/gin-gonic/gin/issues/3555"},
							{Type: osvpb.Reference_FIX, Url: "https://github.com/gin-gonic/gin/pull/3556"},
							{Type: osvpb.Reference_WEB, Url: "https://github.com/gin-gonic/gin/releases/tag/v1.9.1"},
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef:      "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:          "CVE-2020-11978",
					Affects:     &[]cyclonedx.Affects{},
					Description: "CVE-2020-11978",
					Detail:      "CVE-2020-11978",
				},
				{
					BOMRef:      "eb9d18a4-4784-445d-87f3-c67cf22746e9",
					ID:          "CVE-2023-38408",
					Affects:     &[]cyclonedx.Affects{},
					Description: "CVE-2023-38408",
					Detail:      "CVE-2023-38408",
				},
				{
					BOMRef: "95af5a25-3679-41ba-a2ff-6cd471c483f1",
					ID:     "GHSA-2c4m-59x9-fr2g",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-2023-29401", Source: &cyclonedx.Source{}},
						{ID: "GO-2023-1737", Source: &cyclonedx.Source{}},
					},
					Ratings:     &[]cyclonedx.VulnerabilityRating{{Score: new(4.3), Severity: "medium", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"}},
					Affects:     &[]cyclonedx.Affects{},
					Description: "Gin Web Framework does not properly sanitize filename parameter ...",
					Detail:      "The filename parameter of the Context.FileAttachment function is ...",
					Advisories:  &[]cyclonedx.Advisory{{URL: "https://nvd.nist.gov/vuln/detail/CVE-2023-29401"}},
					Published:   "2023-05-12T20:19:25Z",
					Updated:     "2023-11-08T04:12:18Z",
					Rejected:    "",
				},
				{
					BOMRef: "5fb90bad-b37c-4821-b6d9-5526a41a9504",
					ID:     "GO-2023-1737",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-2023-29401", Source: &cyclonedx.Source{}},
						{ID: "GHSA-2c4m-59x9-fr2g", Source: &cyclonedx.Source{}},
					},
					Affects:     &[]cyclonedx.Affects{},
					Description: "Improper handling of filenames in Content-Disposition HTTP heade...",
					Detail:      "The filename parameter of the Context.FileAttachment function is ...",
					Published:   "2023-05-11T18:59:56Z",
					Updated:     "2024-05-20T16:03:47Z",
					Rejected:    "",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							{Name: "motoyasu-saburi"},
						},
					},
				},
				{
					BOMRef: "81855ad8-681d-4d86-91e9-1e00167939cb",
					ID:     "VULN-001",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-111", Source: &cyclonedx.Source{}},
						{ID: "OSV-2", Source: &cyclonedx.Source{}},
					},
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(6.6), Severity: "medium", Method: "CVSSv3", Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"},
						{Score: new(5.7), Severity: "medium", Method: "CVSSv2", Vector: "AV:L/AC:L/Au:S/C:P/I:P/A:C"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
				{
					BOMRef: "6694d2c4-22ac-4208-a007-2939487f6999",
					ID:     "VULN-003",
					References: &[]cyclonedx.VulnerabilityReference{
						{ID: "CVE-111", Source: &cyclonedx.Source{}},
						{ID: "OSV-2", Source: &cyclonedx.Source{}},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "vulnerabilities_with_credits",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Credits: []*osvpb.Credit{
							{Name: "Jane Doe"},
							{Name: "John Doe", Type: osvpb.Credit_SPONSOR},
							{
								Name:    "Example Security Team",
								Contact: []string{"https://example.com/security", "mailto:security@example.com"},
								Type:    osvpb.Credit_REPORTER,
							},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-2",
						Credits: []*osvpb.Credit{
							{Name: "cURL", Type: osvpb.Credit_TOOL},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-3",
						Credits: []*osvpb.Credit{
							{Name: "Jane Doe"},
							{Name: "cURL", Type: osvpb.Credit_TOOL},
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							{Name: "Jane Doe"},
							{Name: "John Doe"},
							{Name: "Example Security Team", Email: "security@example.com"},
						},
					},
					Affects: &[]cyclonedx.Affects{},
				},
				{
					BOMRef:  "81855ad8-681d-4d86-91e9-1e00167939cb",
					ID:      "GHSA-2",
					Affects: &[]cyclonedx.Affects{},
				},
				{
					BOMRef: "6694d2c4-22ac-4208-a007-2939487f6999",
					ID:     "GHSA-3",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							{Name: "Jane Doe"},
						},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "vulnerability_with_credit_contacts",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Credits: []*osvpb.Credit{
							{Name: "Jane Doe", Contact: []string{"mailto:jane@example.com", "mailto:jane@example.org"}},
							{Name: "John Doe", Contact: []string{"https://example.com/john"}},
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Credits: &cyclonedx.Credits{
						Individuals: &[]cyclonedx.OrganizationalContact{
							// only the first email is kept
							{Name: "Jane Doe", Email: "jane@example.com"},
							// contacts that are not emails are dropped
							{Name: "John Doe"},
						},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "advisories_from_advisory_references_only",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						References: []*osvpb.Reference{
							{Type: osvpb.Reference_ADVISORY, Url: "https://example.com/advisory/1"},
							{Type: osvpb.Reference_WEB, Url: "https://example.com/blog"},
							{Type: osvpb.Reference_ADVISORY, Url: "https://example.com/advisory/2"},
							{Type: osvpb.Reference_FIX, Url: "https://example.com/fix"},
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					// all advisories are kept, in their original order
					Advisories: &[]cyclonedx.Advisory{
						{URL: "https://example.com/advisory/1"},
						{URL: "https://example.com/advisory/2"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_ignore_affected_severities",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, // 7.5, high
						},
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "npm", Name: "pkg"},
								Severity: []*osvpb.Severity{
									{Type: osvpb.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, // 9.3, critical
								},
							},
						},
					},
				},
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-2",
						Affected: []*osvpb.Affected{
							{
								Package: &osvpb.Package{Ecosystem: "npm", Name: "pkg"},
								Severity: []*osvpb.Severity{
									{Type: osvpb.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, // 9.3, critical
								},
							},
						},
					},
				},
			},
			// only top-level severities are used for ratings
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(7.5), Severity: "high", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
				{
					BOMRef:  "81855ad8-681d-4d86-91e9-1e00167939cb",
					ID:      "GHSA-2",
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_cvss_v2_v3_v4",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},                                      // 5.0, medium
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},                    // 7.5, high
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},                    // 9.8, critical
							{Type: osvpb.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, // 9.3, critical
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(5.0), Severity: "medium", Method: "CVSSv2", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
						{Score: new(7.5), Severity: "high", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
						{Score: new(9.8), Severity: "critical", Method: "CVSSv3", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
						{Score: new(9.3), Severity: "critical", Method: "CVSSv4", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_differ_across_cvss_versions",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V2, Score: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},                   // 5.0, medium
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, // 7.5, high
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(5.0), Severity: "medium", Method: "CVSSv2", Vector: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
						{Score: new(7.5), Severity: "high", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_zero_score",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"}, // 0.0, none
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(0.0), Severity: "none", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_ignore_unsupported_severity_types",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_Ubuntu, Score: "high"},
							{Type: osvpb.Severity_UNSPECIFIED, Score: "high"},
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, // 7.5, high
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Score: new(7.5), Severity: "high", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_keep_unscorable_vectors",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:X"},                                // invalid metric value
							{Type: osvpb.Severity_CVSS_V3, Score: "not a vector"},                                 // unsupported CVSS_V3 version
							{Type: osvpb.Severity_CVSS_V4, Score: ""},                                             // empty score
							{Type: osvpb.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}, // 7.5, high
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef: "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:     "GHSA-1",
					// invalid vectors are kept without a score, and empty ones are skipped
					Ratings: &[]cyclonedx.VulnerabilityRating{
						{Method: "CVSSv3", Vector: "CVSS:3.1/AV:X"},
						{Method: "CVSSv3", Vector: "not a vector"},
						{Score: new(7.5), Severity: "high", Method: "CVSSv3", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
					},
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
		{
			name: "ratings_only_ignored_severities",
			vulns: []*inventory.PackageVuln{
				{
					Vulnerability: &osvpb.Vulnerability{
						Id: "GHSA-1",
						Severity: []*osvpb.Severity{
							{Type: osvpb.Severity_Ubuntu, Score: "high"},
							{Type: osvpb.Severity_UNSPECIFIED, Score: "high"},
							{Type: osvpb.Severity_CVSS_V3, Score: ""}, // empty score
						},
					},
				},
			},
			want: &[]cyclonedx.Vulnerability{
				{
					BOMRef:  "9566c74d-1003-4c4d-bbbb-0407d1e2c649",
					ID:      "GHSA-1",
					Affects: &[]cyclonedx.Affects{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make UUIDs deterministic
			uuid.SetRand(rand.New(rand.NewSource(1)))

			inv := inventory.Inventory{
				Packages:     []*extractor.Package{},
				PackageVulns: tt.vulns,
			}

			got := converter.ToCDX(inv, converter.CDXConfig{}).Vulnerabilities

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("converter.ToCDX(%v): unexpected vulnerabilities diff (-want +got):\n%s", inv, diff)
			}
		})
	}
}

func TestToCDX_Licenses(t *testing.T) {
	tests := []struct {
		name     string
		licenses []string
		want     *cyclonedx.Licenses
	}{
		{
			name:     "no_licenses",
			licenses: nil,
			want:     nil,
		},
		{
			name:     "empty_licenses",
			licenses: []string{},
			want:     nil,
		},
		{
			name:     "only_empty_licenses",
			licenses: []string{"", ""},
			want:     nil,
		},
		{
			name:     "single_spdx_license",
			licenses: []string{"MIT"},
			want:     &cyclonedx.Licenses{{Expression: "MIT"}},
		},
		{
			name:     "duplicate_spdx_licenses",
			licenses: []string{"MIT", "mit"},
			want:     &cyclonedx.Licenses{{Expression: "MIT"}},
		},
		{
			name:     "spdx_expression",
			licenses: []string{"MIT AND Zlib"},
			want:     &cyclonedx.Licenses{{Expression: "MIT AND Zlib"}},
		},
		{
			name:     "multiple_spdx_licenses",
			licenses: []string{"MIT", "Apache-2.0"},
			want:     &cyclonedx.Licenses{{Expression: "Apache-2.0 AND MIT"}},
		},
		{
			name:     "custom_license",
			licenses: []string{"MIT", "My Custom License"},
			want:     &cyclonedx.Licenses{{Expression: "LicenseRef-My-Custom-License AND MIT"}},
		},
		// the following cannot be represented as an expression, so the list form is used
		{
			name:     "non_standard_license",
			licenses: []string{"non-standard"},
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
			},
		},
		{
			name:     "unknown_license",
			licenses: []string{"unknown"},
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "unknown"}},
			},
		},
		{
			name:     "non_standard_and_spdx_licenses",
			licenses: []string{"non-standard", "Apache-2.0"},
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{ID: "Apache-2.0"}},
			},
		},
		{
			name:     "non_standard_and_spdx_expression",
			licenses: []string{"non-standard", "MIT AND Zlib"},
			// expressions are kept whole, as they cannot be part of the list form
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{Name: "MIT AND Zlib"}},
			},
		},
		{
			name:     "non_standard_and_custom_license",
			licenses: []string{"non-standard", "My Custom License"},
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{Name: "My Custom License"}},
			},
		},
		{
			name:     "non_standard_and_non_canonical_spdx_licenses",
			licenses: []string{"non-standard", "mit", "Apache2"},
			// spdx licenses are normalized to their canonical short identifier
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{ID: "MIT"}},
				{License: &cyclonedx.License{ID: "Apache-2.0"}},
			},
		},
		{
			// based on jakarta.annotation-api from google/osv-scanner#3236
			name:     "non_standard_and_deprecated_spdx_license",
			licenses: []string{"non-standard", "GPL-2.0-with-classpath-exception"},
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{ID: "GPL-2.0-with-classpath-exception"}},
			},
		},
		{
			name:     "non_standard_and_empty_licenses",
			licenses: []string{"", "non-standard", "  "},
			// empty (and whitespace-only) licenses are skipped
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
			},
		},
		{
			name:     "non_standard_and_duplicate_licenses",
			licenses: []string{"non-standard", "MIT", "mit", "non-standard"},
			// licenses are deduplicated after being normalized
			want: &cyclonedx.Licenses{
				{License: &cyclonedx.License{Name: "non-standard"}},
				{License: &cyclonedx.License{ID: "MIT"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv := inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.0.0",
					PURLType: purl.TypeNPM,
					Licenses: tt.licenses,
				}},
			}

			got := (*converter.ToCDX(inv, converter.CDXConfig{}).Components)[0].Licenses

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("converter.ToCDX(%v): unexpected licenses diff (-want +got):\n%s", inv, diff)
			}
		})
	}
}
