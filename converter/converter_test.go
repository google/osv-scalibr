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
	"math/rand"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
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
						BOMRef:     "0bf50598-7592-4e66-8a5b-df2c7fc48445",
						Type:       "library",
						Name:       "non-standard-license",
						Version:    "1.0.0",
						PackageURL: "pkg:npm/non-standard-license@1.0.0",
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
