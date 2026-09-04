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
	"runtime"
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
						BOMRef:  "6694d2c4-22ac-4208-a007-2939487f6999",
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
						BOMRef:     "eb9d18a4-4784-445d-87f3-c67cf22746e9",
						Type:       "library",
						Name:       "software",
						Version:    "1.2.3",
						PackageURL: "pkg:pypi/software@1.2.3",
					},
				}),
			},
		},
		{
			desc: "Packages_with_parent_IDs_emit_dependencies",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:      "parent",
						ID:        "parent-id",
						Version:   "1.0.0",
						PURLType:  purl.TypePyPi,
						ParentIDs: map[string]bool{"root": true},
					},
					{
						Name:      "child",
						ID:        "child-id",
						Version:   "2.0.0",
						PURLType:  purl.TypePyPi,
						ParentIDs: map[string]bool{"parent-id": true, "missing-id": true},
					},
				},
			},
			config: converter.CDXConfig{ComponentName: "sbom-3"},
			want: &cyclonedx.BOM{
				Metadata: &cyclonedx.Metadata{
					Component: &cyclonedx.Component{
						Name:   "sbom-3",
						BOMRef: "5fb90bad-b37c-4821-b6d9-5526a41a9504",
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
						BOMRef:     "680b4e7c-8b76-4a1b-9d49-d4955c848621",
						Type:       "library",
						Name:       "parent",
						Version:    "1.0.0",
						PackageURL: "pkg:pypi/parent@1.0.0",
					},
					{
						BOMRef:     "6325253f-ec73-4dd7-a9e2-8bf921119c16",
						Type:       "library",
						Name:       "child",
						Version:    "2.0.0",
						PackageURL: "pkg:pypi/child@2.0.0",
					},
				}),
				Dependencies: new([]cyclonedx.Dependency{
					{Ref: "5fb90bad-b37c-4821-b6d9-5526a41a9504", Dependencies: new([]string{"680b4e7c-8b76-4a1b-9d49-d4955c848621"})},
					{Ref: "680b4e7c-8b76-4a1b-9d49-d4955c848621", Dependencies: new([]string{"6325253f-ec73-4dd7-a9e2-8bf921119c16"})},
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

func TestToPURL(t *testing.T) {
	tests := []struct {
		desc   string
		pkg    *extractor.Package
		want   *purl.PackageURL
		onGoos string
	}{
		{
			desc: "Valid_package_extractor",
			pkg: &extractor.Package{
				Name:     "software",
				Version:  "1.0.0",
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath("/file1"),
				Plugins:  []string{wheelegg.Name},
			},
			want: &purl.PackageURL{
				Type:    purl.TypePyPi,
				Name:    "software",
				Version: "1.0.0",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.onGoos != "" && tc.onGoos != runtime.GOOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			got := converter.ToPURL(tc.pkg)

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("converter.ToPURL(%v) returned unexpected diff (-want +got):\n%s", tc.pkg, diff)
			}
		})
	}
}
