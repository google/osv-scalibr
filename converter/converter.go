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

// Package converter provides utility functions for converting SCALIBR's scan results to
// standardized inventory formats.
package converter

import (
	"fmt"
	"regexp"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	cdxe "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	spdxe "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
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
	// SPDXDocumentID is the string identifier used to refer to the SPDX document.
	SPDXDocumentID = "SPDXRef-Document"
)

// spdx_id must only contain letters, numbers, "." and "-"
var spdxIDInvalidCharRe = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

// ToPURL converts a SCALIBR package structure into a package URL.
func ToPURL(p *extractor.Package) *purl.PackageURL {
	return p.Extractor.ToPURL(p)
}

// SPDXConfig describes custom settings that should be applied to the generated SPDX file.
type SPDXConfig struct {
	DocumentName      string
	DocumentNamespace string
	Creators          []common.Creator
}

// ToSPDX23 converts the SCALIBR scan results into an SPDX v2.3 document.
func ToSPDX23(r *scalibr.ScanResult, c SPDXConfig) *v2_3.Document {
	packages := make([]*v2_3.Package, 0, len(r.Inventory.Packages)+1)

	// Add a main package that contains all other top-level packages.
	mainPackageID := SPDXRefPrefix + "Package-main-" + uuid.New().String()
	packages = append(packages, &v2_3.Package{
		PackageName:           "main",
		PackageSPDXIdentifier: common.ElementID(mainPackageID),
		PackageVersion:        "0",
		PackageSupplier: &common.Supplier{
			Supplier:     NoAssertion,
			SupplierType: NoAssertion,
		},
		PackageDownloadLocation:   NoAssertion,
		IsFilesAnalyzedTagPresent: false,
	})

	relationships := make([]*v2_3.Relationship, 0, 1+2*len(r.Inventory.Packages))
	relationships = append(relationships, &v2_3.Relationship{
		RefA:         toDocElementID(SPDXDocumentID),
		RefB:         toDocElementID(mainPackageID),
		Relationship: "DESCRIBES",
	})

	for _, pkg := range r.Inventory.Packages {
		p := ToPURL(pkg)
		if p == nil {
			log.Warnf("Package %v has no PURL, skipping", pkg)
			continue
		}
		pName := p.Name
		pVersion := p.Version
		if pName == "" || pVersion == "" {
			log.Warnf("Package %v PURL name or version empty, skipping", pkg)
			continue
		}
		pID := SPDXRefPrefix + "Package-" + replaceSPDXIDInvalidChars(pName) + "-" + uuid.New().String()
		pSourceInfo := fmt.Sprintf("Identified by the %s extractor", pkg.Extractor.Name())
		if len(pkg.Locations) == 1 {
			pSourceInfo += " from " + pkg.Locations[0]
		} else if l := len(pkg.Locations); l > 1 {
			pSourceInfo += fmt.Sprintf(" from %d locations, including %s and %s", l, pkg.Locations[0], pkg.Locations[1])
		}

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
			PackageSourceInfo:         pSourceInfo,
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
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
		{
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

// CDXConfig describes custom settings that should be applied to the generated CDX file.
type CDXConfig struct {
	ComponentName    string
	ComponentVersion string
	Authors          []string
}

// ToCDX converts the SCALIBR scan results into a CycloneDX document.
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
			Components: &[]cyclonedx.Component{
				{
					Type: cyclonedx.ComponentTypeApplication,
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

	comps := make([]cyclonedx.Component, 0, len(r.Inventory.Packages))
	for _, pkg := range r.Inventory.Packages {
		comp := cyclonedx.Component{
			BOMRef:  uuid.New().String(),
			Type:    cyclonedx.ComponentTypeLibrary,
			Name:    pkg.Name,
			Version: pkg.Version,
		}
		if p := ToPURL(pkg); p != nil {
			comp.PackageURL = p.String()
		}
		if cpes := extractCPEs(pkg); len(cpes) > 0 {
			comp.CPE = cpes[0]
		}
		if len(pkg.Locations) > 0 {
			occ := make([]cyclonedx.EvidenceOccurrence, 0, len((pkg.Locations)))
			for _, loc := range pkg.Locations {
				occ = append(occ, cyclonedx.EvidenceOccurrence{
					Location: loc,
				})
			}
			comp.Evidence = &cyclonedx.Evidence{
				Occurrences: &occ,
			}
		}
		comps = append(comps, comp)
	}
	bom.Components = &comps

	return bom
}

func extractCPEs(p *extractor.Package) []string {
	// Only the two SBOM package types support storing CPEs.
	if m, ok := p.Metadata.(*spdxe.Metadata); ok {
		return m.CPEs
	}
	if m, ok := p.Metadata.(*cdxe.Metadata); ok {
		return m.CPEs
	}
	return nil
}
