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

package spdx_test

import (
	"math/rand"
	"testing"

	"github.com/google/go-cmp/cmp"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"
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

	testCases := []struct {
		desc       string
		scanResult *scalibr.ScanResult
		config     spdx.Config
		want       *v2_3.Document
	}{
		{
			desc: "Package_with_no_custom_config",
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
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-9566c74d-1003-4c4d-bbbb-0407d1e2c649",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
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
							ElementRefID: "SPDXRef-DOCUMENT",
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
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
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
			config: spdx.Config{
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
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-eb9d18a4-4784-445d-87f3-c67cf22746e9",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
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
							ElementRefID: "SPDXRef-DOCUMENT",
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
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "Packages_with_licenses",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:     "software-1",
						Version:  "1.2.3",
						PURLType: purl.TypePyPi,
						Licenses: []string{"MIT"},
						Plugins:  []string{wheelegg.Name},
					}, {
						Name:     "software-2",
						Version:  "4.5.6",
						PURLType: purl.TypePyPi,
						Licenses: []string{"Apache-2.0", "MIT", "MADE UP"},
						Plugins:  []string{wheelegg.Name},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/6325253f-ec73-4dd7-a9e2-8bf921119c16",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software-1",
						PackageSPDXIdentifier: "SPDXRef-Package-software-1-5fb90bad-b37c-4821-b6d9-5526a41a9504",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   "MIT",
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software-1@1.2.3",
							},
						},
					},
					{
						PackageName:           "software-2",
						PackageSPDXIdentifier: "SPDXRef-Package-software-2-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						PackageVersion:        "4.5.6",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   "Apache-2.0 AND LicenseRef-MADE-UP AND MIT",
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the python/wheelegg extractor",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:pypi/software-2@4.5.6",
							},
						},
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-1-5fb90bad-b37c-4821-b6d9-5526a41a9504",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-1-5fb90bad-b37c-4821-b6d9-5526a41a9504",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-95af5a25-3679-41ba-a2ff-6cd471c483f1",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-2-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-2-680b4e7c-8b76-4a1b-9d49-d4955c848621",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
				OtherLicenses: []*v2_3.OtherLicense{{LicenseIdentifier: "LicenseRef-MADE-UP", ExtractedText: "MADE UP"}},
			},
		},
		{
			desc: "Package_with_invalid_PURLs_skipped",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{
						// PURL field missing
						{Plugins: []string{wheelegg.Name}},
						// No name
						{
							Version: "1.2.3", PURLType: purl.TypePyPi, Plugins: []string{wheelegg.Name},
						},
						// No version
						{
							Name: "software", PURLType: purl.TypePyPi, Plugins: []string{wheelegg.Name},
						},
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/0bf50598-7592-4e66-8a5b-df2c7fc48445",
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
					PackageSPDXIdentifier: "SPDXRef-Package-main-0f070244-8615-4bda-8831-3f6a8eb668d2",
					PackageVersion:        "0",
					PackageSupplier: &common.Supplier{
						Supplier:     spdx.NoAssertion,
						SupplierType: spdx.NoAssertion,
					},
					PackageDownloadLocation:   spdx.NoAssertion,
					IsFilesAnalyzedTagPresent: false,
				}},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-0f070244-8615-4bda-8831-3f6a8eb668d2",
						},
						Relationship: "DESCRIBES",
					},
				},
			},
		},
		{
			desc: "Invalid_chars_in_package_name_replaced",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:     "softw@re&",
						Version:  "1.2.3",
						PURLType: purl.TypePyPi,
						Plugins:  []string{wheelegg.Name},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/172ed857-94bb-458b-8c3b-525da1786f9f",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "softw@re&",
						PackageSPDXIdentifier: "SPDXRef-Package-softw-re--6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
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
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-92d2572b-cd06-48d2-96c5-2f5054e2d083",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "One_location_reported",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:      "software",
						Version:   "1.2.3",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						Locations: []string{"/file1"},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/29b0223b-eea5-44f7-8391-f445d15afd42",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-255aa5b7-d44b-4c40-b84c-892b9bffd436",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
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
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-ff094279-db19-44eb-97a1-9d0f7bbacbe0",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-255aa5b7-d44b-4c40-b84c-892b9bffd436",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-255aa5b7-d44b-4c40-b84c-892b9bffd436",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
				},
			},
		},
		{
			desc: "Multiple_locations_reported",
			scanResult: &scalibr.ScanResult{
				Inventory: inventory.Inventory{
					Packages: []*extractor.Package{{
						Name:      "software",
						Version:   "1.2.3",
						Plugins:   []string{wheelegg.Name},
						PURLType:  purl.TypePyPi,
						Locations: []string{"/file1", "/file2", "/file3"},
					}},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/b14323a6-bc8f-4e7d-b1d9-29333ff99393",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-94040374-f692-4b98-8bf8-713f8d962d7c",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "software",
						PackageSPDXIdentifier: "SPDXRef-Package-software-8d019192-c242-44e2-8afc-cae3a61fb586",
						PackageVersion:        "1.2.3",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
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
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-94040374-f692-4b98-8bf8-713f8d962d7c",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-94040374-f692-4b98-8bf8-713f8d962d7c",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-8d019192-c242-44e2-8afc-cae3a61fb586",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-8d019192-c242-44e2-8afc-cae3a61fb586",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
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
