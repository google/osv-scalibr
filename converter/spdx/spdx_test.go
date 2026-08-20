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
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/converter"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

func TestToSPDX23(t *testing.T) {
	// Make UUIDs deterministic
	uuid.SetRand(rand.New(rand.NewSource(1)))

	testCases := []struct {
		desc   string
		inv    inventory.Inventory
		config spdx.Config
		want   *v2_3.Document
	}{
		{
			desc: "Package_with_no_custom_config",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
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
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
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
			inv: inventory.Inventory{
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
			desc: "Package_without_name_skipped_versionless_package_kept",
			inv: inventory.Inventory{
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
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/92d2572b-cd06-48d2-96c5-2f5054e2d083",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-0f070244-8615-4bda-8831-3f6a8eb668d2",
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
						PackageSPDXIdentifier: "SPDXRef-Package-software-0bf50598-7592-4e66-8a5b-df2c7fc48445",
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
								Locator:  "pkg:pypi/software",
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
							ElementRefID: "SPDXRef-Package-main-0f070244-8615-4bda-8831-3f6a8eb668d2",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-0f070244-8615-4bda-8831-3f6a8eb668d2",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-0bf50598-7592-4e66-8a5b-df2c7fc48445",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-0bf50598-7592-4e66-8a5b-df2c7fc48445",
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
			desc: "Invalid_chars_in_package_name_replaced",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "softw@re&",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/ff094279-db19-44eb-97a1-9d0f7bbacbe0",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
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
						PackageSPDXIdentifier: "SPDXRef-Package-softw-re--172ed857-94bb-458b-8c3b-525da1786f9f",
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
							ElementRefID: "SPDXRef-Package-main-6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-6bf84c71-74cb-4476-b64c-c3dbd968b0f7",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--172ed857-94bb-458b-8c3b-525da1786f9f",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-softw-re--172ed857-94bb-458b-8c3b-525da1786f9f",
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
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
					Location: extractor.LocationFromPath("/file1"),
				}},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/94040374-f692-4b98-8bf8-713f8d962d7c",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-255aa5b7-d44b-4c40-b84c-892b9bffd436",
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
						PackageSPDXIdentifier: "SPDXRef-Package-software-29b0223b-eea5-44f7-8391-f445d15afd42",
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
				Files: []*v2_3.File{
					{
						FileName:           "/file1",
						FileSPDXIdentifier: "SPDXRef-File--file1-7c9d66ac",
						Checksums: []common.Checksum{
							{
								Algorithm: common.SHA256,
								Value:     spdx.EmptyFileDigest,
							},
						},
						FileCopyrightText: spdx.NoAssertion,
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-DOCUMENT",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-255aa5b7-d44b-4c40-b84c-892b9bffd436",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-255aa5b7-d44b-4c40-b84c-892b9bffd436",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-29b0223b-eea5-44f7-8391-f445d15afd42",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-29b0223b-eea5-44f7-8391-f445d15afd42",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-File--file1-7c9d66ac",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-29b0223b-eea5-44f7-8391-f445d15afd42",
						},
						Relationship: "DEPENDENCY_MANIFEST_OF",
					},
				},
			},
		},
		{
			desc: "related_locations_reported",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					Name:     "software",
					Version:  "1.2.3",
					Plugins:  []string{wheelegg.Name},
					PURLType: purl.TypePyPi,
					Location: extractor.PackageLocation{
						Related: []location.Location{
							{File: &location.File{Path: "/file1"}},
							{File: &location.File{Path: "/file2"}},
							{File: &location.File{Path: "/file3"}},
						},
					},
				}},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/3bea6f5b-3af6-4e03-b436-6c4719e43a1b",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-8d019192-c242-44e2-8afc-cae3a61fb586",
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
						PackageSPDXIdentifier: "SPDXRef-Package-software-b14323a6-bc8f-4e7d-b1d9-29333ff99393",
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
							ElementRefID: "SPDXRef-Package-main-8d019192-c242-44e2-8afc-cae3a61fb586",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-8d019192-c242-44e2-8afc-cae3a61fb586",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-b14323a6-bc8f-4e7d-b1d9-29333ff99393",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-b14323a6-bc8f-4e7d-b1d9-29333ff99393",
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
			desc: "Package_with_custom_package_id",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{{
					ID:       "pkg-custom-id-123",
					Name:     "software",
					Version:  "1.2.3",
					PURLType: purl.TypePyPi,
					Plugins:  []string{wheelegg.Name},
				}},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/4c7215a3-b539-4b1e-9849-c6077dbb5722",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-067d89bc-7f01-41f5-b398-1659a44ff17a",
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
						PackageSPDXIdentifier: "SPDXRef-Package-software-pkg-custom-id-123",
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
							ElementRefID: "SPDXRef-Package-main-067d89bc-7f01-41f5-b398-1659a44ff17a",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-067d89bc-7f01-41f5-b398-1659a44ff17a",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-pkg-custom-id-123",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-software-pkg-custom-id-123",
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
			desc: "Packages_with_dependency_graph",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						ID:        "pkg-parent",
						Name:      "parent-pkg",
						Version:   "1.0.0",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						ParentIDs: map[string]bool{"root": true},
					},
					{
						ID:        "pkg-child",
						Name:      "child-pkg",
						Version:   "2.0.0",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						ParentIDs: map[string]bool{"pkg-parent": true},
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/0b4b3739-7011-4e82-ad6f-4125c8fa7311",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-f5717a28-9a26-4f97-a479-81998ebea89c",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "parent-pkg",
						PackageSPDXIdentifier: "SPDXRef-Package-parent-pkg-pkg-parent",
						PackageVersion:        "1.0.0",
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
								Locator:  "pkg:pypi/parent-pkg@1.0.0",
							},
						},
					},
					{
						PackageName:           "child-pkg",
						PackageSPDXIdentifier: "SPDXRef-Package-child-pkg-pkg-child",
						PackageVersion:        "2.0.0",
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
								Locator:  "pkg:pypi/child-pkg@2.0.0",
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
							ElementRefID: "SPDXRef-Package-main-f5717a28-9a26-4f97-a479-81998ebea89c",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-f5717a28-9a26-4f97-a479-81998ebea89c",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg-pkg-parent",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg-pkg-parent",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-f5717a28-9a26-4f97-a479-81998ebea89c",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-child-pkg-pkg-child",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-child-pkg-pkg-child",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg-pkg-parent",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-child-pkg-pkg-child",
						},
						Relationship: "DEPENDS_ON",
					},
				},
			},
		},
		{
			desc: "Packages_with_multi_parent_dependency_graph",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						ID:        "pkg-parent1",
						Name:      "parent-pkg1",
						Version:   "1.0.0",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						ParentIDs: map[string]bool{"root": true},
					},
					{
						ID:        "pkg-parent2",
						Name:      "parent-pkg2",
						Version:   "1.0.0",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						ParentIDs: map[string]bool{"root": true},
					},
					{
						ID:        "pkg-shared-child",
						Name:      "shared-child",
						Version:   "2.0.0",
						PURLType:  purl.TypePyPi,
						Plugins:   []string{wheelegg.Name},
						ParentIDs: map[string]bool{"pkg-parent1": true, "pkg-parent2": true},
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/24abf7df-866b-4a56-8383-67ad6145de1e",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-e4d7defa-922d-4ae7-b866-67f7e936cd4f",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "parent-pkg1",
						PackageSPDXIdentifier: "SPDXRef-Package-parent-pkg1-pkg-parent1",
						PackageVersion:        "1.0.0",
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
								Locator:  "pkg:pypi/parent-pkg1@1.0.0",
							},
						},
					},
					{
						PackageName:           "parent-pkg2",
						PackageSPDXIdentifier: "SPDXRef-Package-parent-pkg2-pkg-parent2",
						PackageVersion:        "1.0.0",
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
								Locator:  "pkg:pypi/parent-pkg2@1.0.0",
							},
						},
					},
					{
						PackageName:           "shared-child",
						PackageSPDXIdentifier: "SPDXRef-Package-shared-child-pkg-shared-child",
						PackageVersion:        "2.0.0",
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
								Locator:  "pkg:pypi/shared-child@2.0.0",
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
							ElementRefID: "SPDXRef-Package-main-e4d7defa-922d-4ae7-b866-67f7e936cd4f",
						},
						Relationship: "DESCRIBES",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-e4d7defa-922d-4ae7-b866-67f7e936cd4f",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg1-pkg-parent1",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg1-pkg-parent1",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-e4d7defa-922d-4ae7-b866-67f7e936cd4f",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg2-pkg-parent2",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg2-pkg-parent2",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-main-e4d7defa-922d-4ae7-b866-67f7e936cd4f",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-shared-child-pkg-shared-child",
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-shared-child-pkg-shared-child",
						},
						RefB: common.DocElementID{
							SpecialID: spdx.NoAssertion,
						},
						Relationship: "CONTAINS",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg1-pkg-parent1",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-shared-child-pkg-shared-child",
						},
						Relationship: "DEPENDS_ON",
					},
					{
						RefA: common.DocElementID{
							ElementRefID: "SPDXRef-Package-parent-pkg2-pkg-parent2",
						},
						RefB: common.DocElementID{
							ElementRefID: "SPDXRef-Package-shared-child-pkg-shared-child",
						},
						Relationship: "DEPENDS_ON",
					},
				},
			},
		},
		{
			desc: "Packages_with_vendor_dependency_graph",
			inv: inventory.Inventory{
				Packages: []*extractor.Package{
					{
						Name:     "rbe_input_root/github/artfs",
						Version:  "local-fork",
						PURLType: purl.TypeGeneric,
						Plugins:  []string{"misc/some_metadata_scanner"},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo:   "https://github.com/ywmei-brt1/artfs",
							Commit: "624bf058e5b4d18428784d7735794054845f9c1d",
						},
						Location: extractor.LocationFromPath("rbe_input_root/github/artfs/METADATA"),
					},
					{
						Name:     "rbe_input_root/github/artfs/vendor/libfuse",
						Version:  "local-fork",
						PURLType: purl.TypeGeneric,
						Plugins:  []string{"misc/some_metadata_scanner"},
						SourceCode: &extractor.SourceCodeIdentifier{
							Repo:   "https://github.com/libfuse/libfuse",
							Commit: "033844748010a3b8265bf1c90b9ae8ffe4cd9ca7",
						},
						Location:  extractor.LocationFromPath("rbe_input_root/github/artfs/vendor/libfuse/METADATA"),
						ParentIDs: map[string]bool{"rbe_input_root/github/artfs": true},
					},
				},
			},
			want: &v2_3.Document{
				SPDXVersion:       "SPDX-2.3",
				DataLicense:       "CC0-1.0",
				SPDXIdentifier:    "DOCUMENT",
				DocumentName:      "SCALIBR-generated SPDX",
				DocumentNamespace: "https://spdx.google/9f8e4da6-4301-4522-8d0b-29688b734b8e",
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
						PackageSPDXIdentifier: "SPDXRef-Package-main-e8f4a8b0-993e-4df8-883a-0ad8be9c3978",
						PackageVersion:        "0",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
					},
					{
						PackageName:           "rbe_input_root/github/artfs",
						PackageSPDXIdentifier: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec",
						PackageVersion:        "local-fork",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the misc/some_metadata_scanner extractor from rbe_input_root/github/artfs/METADATA",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/rbe_input_root%2Fgithub%2Fartfs@local-fork",
							},
						},
					},
					{
						PackageName:           "rbe_input_root/github/artfs/vendor/libfuse",
						PackageSPDXIdentifier: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5",
						PackageVersion:        "local-fork",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the misc/some_metadata_scanner extractor from rbe_input_root/github/artfs/vendor/libfuse/METADATA",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:generic/rbe_input_root%2Fgithub%2Fartfs%2Fvendor%2Flibfuse@local-fork",
							},
						},
					},
					{
						PackageName:           "ywmei-brt1/artfs",
						PackageSPDXIdentifier: "SPDXRef-Package-ywmei-brt1-artfs-624bf058e5b4d18428784d7735794054845f9c1d",
						PackageVersion:        "624bf058e5b4d18428784d7735794054845f9c1d",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the misc/some_metadata_scanner extractor from rbe_input_root/github/artfs/METADATA",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:github/ywmei-brt1/artfs@624bf058e5b4d18428784d7735794054845f9c1d",
							},
						},
					},
					{
						PackageName:           "libfuse/libfuse",
						PackageSPDXIdentifier: "SPDXRef-Package-libfuse-libfuse-033844748010a3b8265bf1c90b9ae8ffe4cd9ca7",
						PackageVersion:        "033844748010a3b8265bf1c90b9ae8ffe4cd9ca7",
						PackageSupplier: &common.Supplier{
							Supplier:     spdx.NoAssertion,
							SupplierType: spdx.NoAssertion,
						},
						PackageDownloadLocation:   spdx.NoAssertion,
						PackageLicenseConcluded:   spdx.NoAssertion,
						PackageLicenseDeclared:    spdx.NoAssertion,
						IsFilesAnalyzedTagPresent: false,
						PackageSourceInfo:         "Identified by the misc/some_metadata_scanner extractor from rbe_input_root/github/artfs/vendor/libfuse/METADATA",
						PackageExternalReferences: []*v2_3.PackageExternalReference{
							{
								Category: "PACKAGE-MANAGER",
								RefType:  "purl",
								Locator:  "pkg:github/libfuse/libfuse@033844748010a3b8265bf1c90b9ae8ffe4cd9ca7",
							},
						},
					},
				},
				Files: []*v2_3.File{
					{
						FileName:           "rbe_input_root/github/artfs/METADATA",
						FileSPDXIdentifier: "SPDXRef-File-rbe-input-root-github-artfs-METADATA-3b761aba",
						Checksums: []common.Checksum{
							{
								Algorithm: common.SHA256,
								Value:     spdx.EmptyFileDigest,
							},
						},
						FileCopyrightText: spdx.NoAssertion,
					},
					{
						FileName:           "rbe_input_root/github/artfs/vendor/libfuse/METADATA",
						FileSPDXIdentifier: "SPDXRef-File-rbe-input-root-github-artfs-vendor-libfuse-METADATA-5c16f292",
						Checksums: []common.Checksum{
							{
								Algorithm: common.SHA256,
								Value:     spdx.EmptyFileDigest,
							},
						},
						FileCopyrightText: spdx.NoAssertion,
					},
				},
				Relationships: []*v2_3.Relationship{
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-DOCUMENT"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-main-e8f4a8b0-993e-4df8-883a-0ad8be9c3978"},
						Relationship: "DESCRIBES",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-main-e8f4a8b0-993e-4df8-883a-0ad8be9c3978"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec"},
						RefB:         common.DocElementID{SpecialID: "NOASSERTION"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-File-rbe-input-root-github-artfs-METADATA-3b761aba"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec"},
						Relationship: "DEPENDENCY_MANIFEST_OF",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-ywmei-brt1-artfs-624bf058e5b4d18428784d7735794054845f9c1d"},
						Relationship: "DESCENDANT_OF",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-main-e8f4a8b0-993e-4df8-883a-0ad8be9c3978"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5"},
						RefB:         common.DocElementID{SpecialID: "NOASSERTION"},
						Relationship: "CONTAINS",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-b04883e5-6a15-4a8d-a563-afa467d49dec"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5"},
						Relationship: "DEPENDS_ON",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-File-rbe-input-root-github-artfs-vendor-libfuse-METADATA-5c16f292"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5"},
						Relationship: "DEPENDENCY_MANIFEST_OF",
					},
					{
						RefA:         common.DocElementID{ElementRefID: "SPDXRef-Package-rbe-input-root-github-artfs-vendor-libfuse-6a40e9a1-d007-4033-8282-3061bdd0eaa5"},
						RefB:         common.DocElementID{ElementRefID: "SPDXRef-Package-libfuse-libfuse-033844748010a3b8265bf1c90b9ae8ffe4cd9ca7"},
						Relationship: "DESCENDANT_OF",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := converter.ToSPDX23(tc.inv, tc.config)
			// Can't mock time.Now() so skip verifying the timestamp.
			tc.want.CreationInfo.Created = got.CreationInfo.Created

			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(v2_3.Package{})); diff != "" {
				t.Errorf("converter.ToSPDX23(%v): unexpected diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}

func TestGetFileSHA256(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	content := "hello world"
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", testFile, err)
	}

	wantSHA256 := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

	tests := []struct {
		name     string
		path     string
		rootPath string
		want     string
	}{
		{
			name:     "absolute_path_exists",
			path:     testFile,
			rootPath: "",
			want:     wantSHA256,
		},
		{
			name:     "relative_path_with_rootPath_exists",
			path:     "test.txt",
			rootPath: tempDir,
			want:     wantSHA256,
		},
		{
			name:     "file_does_not_exist",
			path:     filepath.Join(tempDir, "nonexistent.txt"),
			rootPath: "",
			want:     spdx.EmptyFileDigest,
		},
		{
			name:     "absolute_path_with_rootPath_ignores_rootPath",
			path:     testFile,
			rootPath: tempDir,
			want:     wantSHA256,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := spdx.GetFileSHA256(tc.path, tc.rootPath)
			if got != tc.want {
				t.Errorf("GetFileSHA256(%q, %q) = %q, want %q", tc.path, tc.rootPath, got, tc.want)
			}
		})
	}
}

func TestGetSourceCodePURL(t *testing.T) {
	tests := []struct {
		name    string
		repoURL string
		commit  string
		want    *purl.PackageURL
	}{
		{
			name:    "github_https_url",
			repoURL: "https://github.com/square/okhttp",
			commit:  "4984568367caaf359b82c452bd28b5e192824d1c",
			want: &purl.PackageURL{
				Type:      purl.TypeGithub,
				Namespace: "square",
				Name:      "okhttp",
				Version:   "4984568367caaf359b82c452bd28b5e192824d1c",
			},
		},
		{
			name:    "github_http_url",
			repoURL: "http://github.com/square/okhttp",
			commit:  "abc1234",
			want: &purl.PackageURL{
				Type:      purl.TypeGithub,
				Namespace: "square",
				Name:      "okhttp",
				Version:   "abc1234",
			},
		},
		{
			name:    "generic_gitlab_url",
			repoURL: "https://gitlab.gnome.org/GNOME/libxml2",
			commit:  "04af2cabb9f859c198b8a553c028a87481199410",
			want: &purl.PackageURL{
				Type:    purl.TypeGeneric,
				Name:    "gitlab.gnome.org/GNOME/libxml2",
				Version: "04af2cabb9f859c198b8a553c028a87481199410",
			},
		},
		{
			name:    "github_url_without_repo",
			repoURL: "https://github.com/norepo",
			commit:  "def5678",
			want: &purl.PackageURL{
				Type:    purl.TypeGeneric,
				Name:    "github.com/norepo",
				Version: "def5678",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := spdx.GetSourceCodePURL(tc.repoURL, tc.commit)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("GetSourceCodePURL(%q, %q) mismatch (-want +got):\n%s", tc.repoURL, tc.commit, diff)
			}
		})
	}
}
