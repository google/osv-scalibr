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

package converter_test

import (
	"math/rand"
	"runtime"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
)

func ptr[T any](v T) *T {
	return &v
}

func TestToCDX(t *testing.T) {
	// Make UUIDs deterministic
	uuid.SetRand(rand.New(rand.NewSource(1)))
	defaultBOM := cyclonedx.NewBOM()

	testCases := []struct {
		desc       string
		scanResult *scalibr.ScanResult
		config     converter.CDXConfig
		want       *cyclonedx.BOM
	}{
		{
			desc: "Package_with_custom_config",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:     "software",
						Version:  "1.2.3",
						PURLType: purl.TypePyPi,
						Plugins:  []string{wheelegg.Name},
					}},
				},
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
					Authors: ptr([]cyclonedx.OrganizationalContact{{Name: "author"}}),
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: ptr([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: ptr([]cyclonedx.Component{
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
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:     "software",
						Version:  "1.2.3",
						PURLType: purl.TypePyPi,
						Plugins:  []string{wheelegg.Name},
					}},
				},
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
					Authors: ptr([]cyclonedx.OrganizationalContact{{Name: "author"}}),
					Tools: &cyclonedx.ToolsChoice{
						Components: &[]cyclonedx.Component{
							{
								Type: cyclonedx.ComponentTypeApplication,
								Name: "SCALIBR",
								ExternalReferences: ptr([]cyclonedx.ExternalReference{
									{URL: "https://github.com/google/osv-scalibr", Type: cyclonedx.ERTypeWebsite},
								}),
							},
						},
					},
				},
				Components: ptr([]cyclonedx.Component{
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
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToCDX(tc.scanResult, tc.config)
			// Can't mock time.Now() so skip verifying the timestamp.
			tc.want.Metadata.Timestamp = got.Metadata.Timestamp
			// Auto-populated fields
			tc.want.XMLNS = defaultBOM.XMLNS
			tc.want.JSONSchema = defaultBOM.JSONSchema
			tc.want.BOMFormat = defaultBOM.BOMFormat
			tc.want.SpecVersion = defaultBOM.SpecVersion
			tc.want.Version = defaultBOM.Version

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("converter.ToCDX(%v): unexpected diff (-want +got):\n%s", tc.scanResult, diff)
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
				Name:      "software",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"/file1"},
				Plugins:   []string{wheelegg.Name},
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
