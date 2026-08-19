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

// Package converter provides utility functions for converting SCALIBR's scan results to
// standardized inventory formats.
package converter

import (
	"maps"
	"slices"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/converter/spdx"
	"github.com/google/osv-scalibr/extractor"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
)

// ToPURL converts a SCALIBR package structure into a package URL.
func ToPURL(p *extractor.Package) *purl.PackageURL {
	return p.PURL()
}

// ToSPDX23 converts the SCALIBR scan results into an SPDX v2.3 document.
func ToSPDX23(i inventory.Inventory, c spdx.Config) *v2_3.Document {
	return spdx.ToSPDX23(i, c)
}

// CDXConfig describes custom settings that should be applied to the generated CDX file.
type CDXConfig struct {
	ComponentName    string
	ComponentVersion string
	ComponentType    string
	Authors          []string
}

// ToCDX converts the SCALIBR scan results into a CycloneDX document.
func ToCDX(i inventory.Inventory, c CDXConfig) *cyclonedx.BOM {
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

	comps := make([]cyclonedx.Component, 0, len(i.Packages))
	scalibrToBOMRef := make(map[string]string)
	pkgToBOMRef := make(map[*extractor.Package]string)
	for _, pkg := range i.Packages {
		bomRef := uuid.New().String()
		indexBOMRefByIDAndName(pkg, bomRef, scalibrToBOMRef, pkgToBOMRef)
		comps = append(comps, toComponent(pkg, bomRef))
	}
	bom.Components = &comps
	edges := dependencyEdgesByParentRef(i.Packages, pkgToBOMRef, scalibrToBOMRef, bom.Metadata.Component.BOMRef)
	if deps := toSortedDependencies(edges); len(deps) > 0 {
		bom.Dependencies = &deps
	}

	return bom
}

// indexBOMRefByIDAndName records bomRef under the package's SCALIBR ID and, when
// set, its name, so that ParentIDs referring to either can be resolved later.
// The package is left out of the index if no ID can be generated for it.
func indexBOMRefByIDAndName(
	pkg *extractor.Package,
	bomRef string,
	scalibrToBOMRef map[string]string,
	pkgToBOMRef map[*extractor.Package]string,
) {
	id, err := pkg.GetIDOrGenerate()
	if err != nil {
		log.Warnf("Failed to get or generate ID for package %v: %v", pkg, err)
		return
	}
	scalibrToBOMRef[id] = bomRef
	if pkg.Name != "" {
		scalibrToBOMRef[pkg.Name] = bomRef
	}
	pkgToBOMRef[pkg] = bomRef
}

// toComponent converts a SCALIBR package into a CycloneDX library component.
func toComponent(pkg *extractor.Package, bomRef string) cyclonedx.Component {
	comp := cyclonedx.Component{
		BOMRef:  bomRef,
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
	occ := []cyclonedx.EvidenceOccurrence{}
	occ = appendOccurrenceFromLocation(pkg.Location.Descriptor, occ)
	for _, r := range pkg.Location.Related {
		occ = appendOccurrenceFromLocation(&r, occ)
	}
	if len(occ) > 0 {
		comp.Evidence = &cyclonedx.Evidence{
			Occurrences: &occ,
		}
	}
	return comp
}

// dependencyEdgesByParentRef inverts the packages' ParentIDs into a set of
// dependent BOM refs per parent BOM ref, warning about unresolvable parents.
func dependencyEdgesByParentRef(
	pkgs []*extractor.Package,
	pkgToBOMRef map[*extractor.Package]string,
	scalibrToBOMRef map[string]string,
	rootRef string,
) map[string]map[string]bool {
	edges := make(map[string]map[string]bool)
	for _, pkg := range pkgs {
		ref, ok := pkgToBOMRef[pkg]
		if !ok {
			continue
		}
		for _, parentID := range slices.Sorted(maps.Keys(pkg.ParentIDs)) {
			parentRef, ok := parentBOMRef(parentID, scalibrToBOMRef, rootRef)
			if !ok {
				log.Warnf("Parent package ID %q for package %v not found in inventory", parentID, pkg)
				continue
			}
			if _, ok := edges[parentRef]; !ok {
				edges[parentRef] = make(map[string]bool)
			}
			edges[parentRef][ref] = true
		}
	}
	return edges
}

// parentBOMRef resolves a SCALIBR parent ID to a BOM ref, mapping the
// synthetic "root" parent to the document's main component.
func parentBOMRef(parentID string, scalibrToBOMRef map[string]string, rootRef string) (string, bool) {
	if ref, ok := scalibrToBOMRef[parentID]; ok {
		return ref, true
	}
	if parentID == "root" {
		return rootRef, true
	}
	return "", false
}

// toSortedDependencies flattens the dependency edges into CycloneDX entries,
// with both the entries and their dependency lists sorted by BOM ref.
func toSortedDependencies(edges map[string]map[string]bool) []cyclonedx.Dependency {
	deps := make([]cyclonedx.Dependency, 0, len(edges))
	for _, ref := range slices.Sorted(maps.Keys(edges)) {
		refs := slices.Sorted(maps.Keys(edges[ref]))
		deps = append(deps, cyclonedx.Dependency{
			Ref:          ref,
			Dependencies: &refs,
		})
	}
	return deps
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

func appendOccurrenceFromLocation(l *location.Location, occ []cyclonedx.EvidenceOccurrence) []cyclonedx.EvidenceOccurrence {
	if l != nil && l.File != nil {
		occ = append(occ, cyclonedx.EvidenceOccurrence{
			Location: l.File.Path,
		})
	}
	return occ
}
