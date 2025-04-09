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
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func TestToSPDX23(t *testing.T) {
	// Make UUIDs deterministic
	uuid.SetRand(rand.New(rand.NewSource(1)))
	pipEx := wheelegg.New(wheelegg.DefaultConfig())

	testCases := []struct {
		desc       string
		scanResult *scalibr.ScanResult
		config     converter.SPDXConfig
		want       *v2_3.Document
	}{
		{
			desc: "Package with no custom config",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "software", Version: "1.2.3", Extractor: pipEx,
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/81855ad8-681d-4d86-91e9-1e00167939cb",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
					},
				},
				Packages: []*v2_3.Package{
					{
						PackageName:           "main",
						PackageSPDXIdentifier: "SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software@1.2.3",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-52fdfc07-2182-454f-963f-5f0f9a621d72",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649",
						},
						RefB: common.DocElementID{
							SpecialID: converter.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "Package with custom config",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "software", Version: "1.2.3", Extractor: pipEx,
					}},
				},
			},
			config: converter.SPDXConfig{
				DocumentName:      "Custom name",
				DocumentNamespace: "Custom namespace",
				Creators: []common.Creator{
					{
						CreatorType: "Person",
						Creator:     "Custom creator",
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "Custom name",
				DocumentNamespace: "Custom namespace",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
						{
							CreatorType: "Person",
							Creator:     "Custom creator",
						},
					},
				},
				Packages: []*v2_3.Package{
					{
						PackageName:           "main",
						PackageSPDXIdentifier: "SPDXRef-Package-main-6694d2c4-22ac-4208-a007-2939487f6999",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-eb9d18a4-4784-445d-87f3-c67cf22746e9",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software@1.2.3",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-6694d2c4-22ac-4208-a007-2939487f6999",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-6694d2c4-22ac-4208-a007-2939487f6999",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-eb9d18a4-4784-445d-87f3-c67cf22746e9",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-eb9d18a4-4784-445d-87f3-c67cf22746e9",
						},
						RefB: common.DocElementID{
							SpecialID: converter.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "Package with invalid PURLs skipped",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						// PURL field missing
						{Extractor: pipEx},
						// No name
						{
							Version: "1.2.3", Extractor: pipEx,
						},
						// No version
						{
							Name: "software", Extractor: pipEx,
						},
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/5fb90bad-b37c-4821-b6d9-5526a41a9504",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
					},
				},
				Packages: []*v2_3.Package{{
					PackageName:           "main",
					PackageSPDXIdentifier: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
					PackageVersion:        "0",
					PackageSupplier: &common.Supplier{
						Supplier:     converter.NoAssertion,
						SupplierType: converter.NoAssertion,
					},
					PackageDownloadLocation:   converter.NoAssertion,
					IsFilesAnalyzedTagPresent: false,
				}},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
						},
						Relationship: "DESCRIBES",
					},
				},
			},
		},
		{
			desc: "Invalid chars in package name replaced",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "softw@re&", Version: "1.2.3", Extractor: pipEx,
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/0f070244-8615-4bda-8831-3f6a8eb668d2",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
					},
				},
				Packages: []*v2_3.Package{
					{
						PackageName:           "main",
						PackageSPDXIdentifier: "SPDXRef-Package-main-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "softw@re&",
						PackageSPDXIdentifier: "SPDXRef-Package-softw-re--6325253f-ec73-4dd7-a9e2-8bf921119c16",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/softw%40re%26@1.2.3",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--6325253f-ec73-4dd7-a9e2-8bf921119c16",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--6325253f-ec73-4dd7-a9e2-8bf921119c16",
						},
						RefB: common.DocElementID{
							SpecialID: converter.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "One location reported",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "software", Version: "1.2.3", Extractor: pipEx, Locations: []string{"/file1"},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
					},
				},
				Packages: []*v2_3.Package{
					{
						PackageName:           "main",
						PackageSPDXIdentifier: "SPDXRef-Package-main-0bf50598-7592-4e66-8a5b-df2c7fc48445",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor from /file1",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software@1.2.3",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-0bf50598-7592-4e66-8a5b-df2c7fc48445",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-0bf50598-7592-4e66-8a5b-df2c7fc48445",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						},
						RefB: common.DocElementID{
							SpecialID: converter.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "Multiple locations reported",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "software", Version: "1.2.3", Extractor: pipEx, Locations: []string{"/file1", "/file2", "/file3"},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/255aa5b7-d44b-4c40-b84c-892b9bffd436",
				CreationInfo: &v2_3.CreationInfo{
					Creators: []common.Creator{
						{
							CreatorType: "Tool",
							Creator:     "SCALIBR",
						},
					},
				},
				Packages: []*v2_3.Package{
					{
						PackageName:           "main",
						PackageSPDXIdentifier: "SPDXRef-Package-main-172ed857-94bb-458b-8c3b-525da1786f9f",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     converter.NoAssertion,
							SupplierType: converter.NoAssertion,
						},
						PackageDownloadLocation:   converter.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor from 3 locations, including /file1 and /file2",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software@1.2.3",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Document",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-172ed857-94bb-458b-8c3b-525da1786f9f",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-172ed857-94bb-458b-8c3b-525da1786f9f",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						},
						RefB: common.DocElementID{
							SpecialID: converter.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToSPDX23(tc.scanResult, tc.config)
			// Can't mock time.Now() so skip verifying the timestamp.
			tc.want.CreationInfo.Created = got.CreationInfo.Created

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(v2_3.Package{})); diff != "" {
				t.Errorf("converter.ToSPDX23(%v): unexpected diff (-want +got):\n%s", tc.scanResult, diff)
			}
		})
	}
}

func ptr[T any](v T) *T {
	return &v
}

func TestToCDX(t *testing.T) {
	// Make UUIDs deterministic
	uuid.SetRand(rand.New(rand.NewSource(1)))
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	defaultBOM := cyclonedx.NewBOM()

	testCases := []struct {
		desc       string
		scanResult *scalibr.ScanResult
		config     converter.CDXConfig
		want       *cyclonedx.BOM
	}{
		{
			desc: "Package with custom config",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name: "software", Version: "1.2.3", Extractor: pipEx,
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
	pipEx := wheelegg.New(wheelegg.DefaultConfig())
	tests := []struct {
		desc   string
		pkg    *extractor.Package
		want   *purl.PackageURL
		onGoos string
	}{
		{
			desc: "Valid package extractor",
			pkg: &extractor.Package{
				Name:      "software",
				Version:   "1.0.0",
				Locations: []string{"/file1"},
				Extractor: pipEx,
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
