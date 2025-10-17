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
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/extractor"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/result"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// ToPURL converts a SCALIBR package structure into a package URL.
func ToPURL(p *extractor.Package) *purl.PackageURL {
	return p.PURL()
}

// ToSPDX23 converts the SCALIBR scan results into an SPDX v2.3 document.
func ToSPDX23(r *result.ScanResult, c spdx.Config) *v2_3.Document {
	return spdx.ToSPDX23(r, c)
}

// CDXConfig describes custom settings that should be applied to the generated CDX file.
type CDXConfig struct {
	ComponentName    string
	ComponentVersion string
	ComponentType    string
	Authors          []string
}

// ToCDX converts the SCALIBR scan results into a CycloneDX document.
func ToCDX(r *result.ScanResult, c CDXConfig) *cyclonedx.BOM {
	bom := cyclonedx.NewBOM()
	bom.Metadata = &cyclonedx.Metadata{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Component: &cyclonedx.Component{
			Name:    c.ComponentName,
			Version: c.ComponentVersion,
			Type:    cyclonedx.ComponentType(c.ComponentType),
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
	if m, ok := p.Metadata.(*spdxmeta.Metadata); ok {
		return m.CPEs
	}
	if m, ok := p.Metadata.(*cdxmeta.Metadata); ok {
		return m.CPEs
	}
	return nil
}
