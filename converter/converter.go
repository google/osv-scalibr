// Copyright 2024 Google LLC
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

// Package converter provides utility functions for converting SCALIBR's scan results to
// standardized inventory formats.
package converter

import (
	"regexp"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	// NoAssertion indicates that we don't claim anything about the value of a given field.
	NoAssertion = "NOASSERTION"
	// SPDXRefPrefix is the prefix used in reference IDs in the SPDX document.
	SPDXRefPrefix = "SPDXRef-"
)

// spdx_id must only contain letters, numbers, "." and "-"
var spdxIDInvalidCharRe = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

// ToPURL converts a SCALIBR inventory structure into a package URL.
func ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return i.Extractor.ToPURL(i)
}

// ToCPEs converts a SCALIBR inventory structure into CPEs, if they're present in the inventory.
func ToCPEs(i *extractor.Inventory) ([]string, error) {
	return i.Extractor.ToCPEs(i)
}

// SPDXConfig describes custom settings that should be applied to the generated SPDX file.
type SPDXConfig struct {
	DocumentName      string
	DocumentNamespace string
	Creators          []common.Creator
}

// ToSPDX23 converts the SCALIBR scan results into an SPDX v2.3 document.
func ToSPDX23(r *scalibr.ScanResult, c SPDXConfig) *v2_3.Document {
	packages := make([]*v2_3.Package, 0, len(r.Inventories)+1)

	// Add a main package that contains all other top-level packages.
	mainPackageID := SPDXRefPrefix + "Package-main-" + uuid.New().String()
	packages = append(packages, &v2_3.Package{
		PackageName:               "main",
		PackageSPDXIdentifier:     common.ElementID(mainPackageID),
		PackageVersion:            "0",
		PackageDownloadLocation:   NoAssertion,
		IsFilesAnalyzedTagPresent: false,
	})

	relationships := make([]*v2_3.Relationship, 0, 2*len(r.Inventories))

	for _, i := range r.Inventories {
		p, err := ToPURL(i)
		if err != nil {
			log.Warnf("ToPURL(%v): %v, skipping", i, err)
			continue
		}
		if p == nil {
			log.Warnf("Inventory %v has no PURL, skipping", i)
			continue
		}
		pName := p.Name
		pVersion := p.Version
		if pName == "" || pVersion == "" {
			log.Warnf("Inventory %v PURL name or version empty, skipping", i)
			continue
		}
		pID := SPDXRefPrefix + "Package-" + replaceSPDXIDInvalidChars(pName) + "-" + uuid.New().String()

		packages = append(packages, &v2_3.Package{
			PackageName:           pName,
			PackageSPDXIdentifier: common.ElementID(pID),
			PackageVersion:        pVersion,
			PackageSupplier: &common.Supplier{
				Supplier:     NoAssertion,
				SupplierType: NoAssertion,
			},
			PackageDownloadLocation:   NoAssertion,
			IsFilesAnalyzedTagPresent: false,
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				&v2_3.PackageExternalReference{
					Category: "PACKAGE-MANAGER",
					RefType:  "purl",
					Locator:  p.String(),
				},
			},
		})
		// TODO(b/313658493): Add a DESCRIBES relationship or a DocumentDescribes field.
		relationships = append(relationships, &v2_3.Relationship{
			RefA:         toDocElementID(mainPackageID),
			RefB:         toDocElementID(pID),
			Relationship: "CONTAINS",
		})
		relationships = append(relationships, &v2_3.Relationship{
			RefA:         toDocElementID(pID),
			RefB:         toDocElementID(NoAssertion),
			Relationship: "CONTAINS",
		})
	}
	name := c.DocumentName
	if name == "" {
		name = "SCALIBR-generated SPDX"
	}
	namespace := c.DocumentNamespace
	if namespace == "" {
		namespace = "https://spdx.google/" + uuid.New().String()
	}
	creators := []common.Creator{
		common.Creator{
			CreatorType: "Tool",
			Creator:     "SCALIBR",
		},
	}
	creators = append(creators, c.Creators...)
	return &v2_3.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXIdentifier:    "DOCUMENT",
		DocumentName:      name,
		DocumentNamespace: namespace,
		CreationInfo: &v2_3.CreationInfo{
			Creators: creators,
			Created:  time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		},
		Packages:      packages,
		Relationships: relationships,
	}
}

func replaceSPDXIDInvalidChars(id string) string {
	return spdxIDInvalidCharRe.ReplaceAllString(id, "-")
}

func toDocElementID(id string) common.DocElementID {
	if id == NoAssertion {
		return common.DocElementID{
			SpecialID: NoAssertion,
		}
	}
	return common.DocElementID{
		ElementRefID: common.ElementID(id),
	}
}

type CDXConfig struct {
	ComponentName    string
	ComponentVersion string
	Authors          []string
}

func ToCDX(r *scalibr.ScanResult, c CDXConfig) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Component: &cyclonedx.Component{
			Name:    c.ComponentName,
			Version: c.ComponentVersion,
			BOMRef:  uuid.New().String(),
		},
		Tools: &cyclonedx.ToolsChoice{
			Tools: &[]cyclonedx.Tool{
				{
					Name: "SCALIBR",
					ExternalReferences: &[]cyclonedx.ExternalReference{
						{
							URL:  "https://github.com/google/osv-scalibr",
							Type: cyclonedx.ERTypeWebsite,
						},
					},
				},
			},
		},
	}
	if len(c.Authors) > 0 {
		authors := make([]cyclonedx.OrganizationalContact, 0, len(c.Authors))
		for _, author := range c.Authors {
			authors = append(authors, cyclonedx.OrganizationalContact{
				Name: author,
			})
		}
		bom.Metadata.Authors = &authors
	}

	comps := make([]cyclonedx.Component, 0, len(r.Inventories))
	for _, i := range r.Inventories {
		pkg := cyclonedx.Component{
			BOMRef:  uuid.New().String(),
			Type:    cyclonedx.ComponentTypeLibrary,
			Name:    (*i).Name,
			Version: (*i).Version,
		}
		if p, err := ToPURL(i); err == nil {
			pkg.PackageURL = p.String()
		}
		if cpes, err := ToCPEs(i); err == nil && len(cpes) > 0 {
			pkg.CPE = cpes[0]
		}
		if len((*i).Locations) > 0 {
			occ := make([]cyclonedx.EvidenceOccurrence, 0, len(((*i).Locations)))
			for _, loc := range (*i).Locations {
				occ = append(occ, cyclonedx.EvidenceOccurrence{
					Location: loc,
				})
			}
			pkg.Evidence = &cyclonedx.Evidence{
				Occurrences: &occ,
			}
		}
		comps = append(comps, pkg)
	}
	bom.Components = &comps

	return bom
}
