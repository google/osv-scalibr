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

// Package spdx extracts software dependencies from an SPDX SBOM.
package spdx

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	spdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "sbom/spdx"
	// CPE23Type is the CPE 2.3 type for SPDX package external references.
	CPE23Type = "cpe23Type"
	// PURLType is the PURL type for SPDX package external references.
	PURLType = "purl"
)

// parsedPackage is a helper struct to store parsed package data.
type parsedPackage struct {
	pkg     *extractor.Package
	id      string
	hasPURL bool
	hasCPE  bool
}

// Extractor extracts software dependencies from an spdx SBOM.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

type extractFunc = func(io.Reader) (*spdx.Document, error)

// Format support based on https://spdx.dev/resources/use/#documents
var extensionHandlers = map[string]extractFunc{
	".json": json.Read,
	".spdx": tagvalue.Read,
	".yml":  yaml.Read,
	".rdf":  rdf.Read,
	".xml":  rdf.Read,
	// No support for .xsl files because those are too ambiguous and could be many other things.
}

// FileRequired returns true if the specified file is a supported spdx file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// For Windows
	path := filepath.ToSlash(api.Path())

	// SPDX files tend to follow these formats:
	// - <name>.spdx
	// - <name>.spdx.<format>
	// - .spdx.<name>.<format>
	//
	// In all cases, the file either:
	// - Ends with `.spdx`
	// - Contains `.spdx.`
	base := strings.ToLower(filepath.Base(path))
	if !(strings.HasSuffix(base, ".spdx") || strings.Contains(base, ".spdx.")) {
		return false
	}

	parseSbom := findExtractor(path)
	isSupported := parseSbom != nil
	return isSupported
}

// Extract parses the SPDX SBOM and returns a list purls from the SBOM.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	parseSbom := findExtractor(input.Path)

	if parseSbom == nil {
		return inventory.Inventory{}, errors.New("sbom/spdx extractor: Invalid file format, only JSON, YAML, RDF, and TagValue are supported")
	}

	spdxDoc, err := parseSbom(input.Reader)

	if err != nil {
		return inventory.Inventory{}, err
	}

	pkgs := e.convertSpdxDocToPackage(spdxDoc, input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
}

func findExtractor(path string) extractFunc {
	for key := range extensionHandlers {
		if strings.ToLower(filepath.Ext(path)) == key {
			return extensionHandlers[key]
		}
	}

	return nil
}

func (e Extractor) convertSpdxDocToPackage(spdxDoc *spdx.Document, path string) []*extractor.Package {
	pkgByID := make(map[string]*parsedPackage)

	for _, spdxPkg := range spdxDoc.Packages {
		pkg := &extractor.Package{
			Location: extractor.LocationFromPath(path),
			Metadata: &spdxmeta.Metadata{},
		}
		m := pkg.Metadata.(*spdxmeta.Metadata)
		// Set the SPDX ID for the package in the package metadata.
		m.SPDXID = string(spdxPkg.PackageSPDXIdentifier)

		for _, extRef := range spdxPkg.PackageExternalReferences {
			m.ExternalReferences = append(m.ExternalReferences, spdxmeta.ExternalReference{
				Category: extRef.Category,
				RefType:  extRef.RefType,
				Locator:  extRef.Locator,
				Comment:  extRef.ExternalRefComment,
			})

			if extRef.RefType == CPE23Type || extRef.RefType == "http://spdx.org/rdf/references/cpe23Type" {
				m.CPEs = append(m.CPEs, extRef.Locator)
				if pkg.Name == "" {
					pkg.Name = extRef.Locator
				}
			} else if extRef.RefType == PURLType || extRef.RefType == "http://spdx.org/rdf/references/purl" {
				if m.PURL != nil {
					log.Warnf("Multiple PURLs found for same package: %q and %q", m.PURL, extRef.Locator)
				}
				packageURL, err := purl.FromString(extRef.Locator)
				if err != nil {
					log.Warnf("Invalid PURL %q for package: %q", extRef.Locator, spdxPkg.PackageName)
				} else {
					pkg.Name = packageURL.Name
					pkg.Version = packageURL.Version
					m.PURL = &packageURL
					pkg.PURLType = packageURL.Type
				}
			}
		}
		if pkg.Name == "" {
			pkg.Name = spdxPkg.PackageName
		}
		if pkg.Version == "" {
			pkg.Version = spdxPkg.PackageVersion
		}
		pkg.Metadata = m
		hasPURL := m.PURL != nil
		hasCPE := len(m.CPEs) > 0
		if !hasPURL && !hasCPE && len(m.ExternalReferences) == 0 {
			log.Warnf("Neither CPE, PURL, nor external reference found for package: %+v", spdxPkg)
			continue
		}

		id := normalizeElementID(string(spdxPkg.PackageSPDXIdentifier))
		parsed := &parsedPackage{
			pkg:     pkg,
			id:      id,
			hasPURL: hasPURL,
			hasCPE:  hasCPE,
		}
		if id != "" {
			pkgByID[id] = parsed
		}
	}

	// Merge packages based on relationships.
	for _, rel := range spdxDoc.Relationships {
		if rel == nil {
			continue
		}
		var childID, parentID string
		switch strings.ToUpper(strings.TrimSpace(rel.Relationship)) {
		case "DESCENDANT_OF", "DESCENDENT_OF":
			// Node A is the descendant (child) of Node B (parent).
			childID = normalizeElementID(string(rel.RefA.ElementRefID))
			parentID = normalizeElementID(string(rel.RefB.ElementRefID))
		case "ANCESTOR_OF":
			// Node A is the ancestor (parent) of Node B (child).
			parentID = normalizeElementID(string(rel.RefA.ElementRefID))
			childID = normalizeElementID(string(rel.RefB.ElementRefID))
		default:
			continue
		}

		if childID == "" || parentID == "" || childID == parentID {
			continue
		}
		child, hasChild := pkgByID[childID]
		parent, hasParent := pkgByID[parentID]
		if !hasChild || !hasParent {
			continue
		}

		// Packages are removed from the map if they are merged into their parent or child.
		mergeLineagePackages(child, parent, pkgByID)
	}

	results := []*extractor.Package{}
	for _, p := range pkgByID {
		results = append(results, p.pkg)
	}
	return results
}

// normalizeElementID normalizes the SPDX element ID by removing the SPDX prefix and any leading or
// trailing whitespace. This function is not strictly necessary, because the underlying parser
// already trims the "SPDXRef-" prefix, but it is included for defensive measures.
func normalizeElementID(id string) string {
	return strings.TrimPrefix(strings.TrimSpace(id), "SPDXRef-")
}

// A package is considered a "stub" (metadata-only node) if it lacks both a PURL and a CPE. In some
// SBOMs, stub packages only carry provenance metadata (e.g. SourceURI codebase paths or PRs) and
// are linked to upstream source packages via SPDX relationships.
//
// mergeLineagePackages absorbs stub nodes into their corresponding analyzable package so the
// resulting inventory contains complete packages with both ecosystem PURLs and internal source
// URIs.
func mergeLineagePackages(child, parent *parsedPackage, pkgByID map[string]*parsedPackage) {
	childMeta := child.pkg.Metadata.(*spdxmeta.Metadata)
	parentMeta := parent.pkg.Metadata.(*spdxmeta.Metadata)

	childIsStub := !child.hasPURL && !child.hasCPE
	parentIsStub := !parent.hasPURL && !parent.hasCPE

	if childIsStub {
		// Child is a stub (or both are stubs): merge child's metadata into parent and absorb child.
		// This is the most common case for lineage merging.
		mergeExternalReferences(parentMeta, childMeta)
		delete(pkgByID, child.id)
	} else if parentIsStub {
		// Parent is a stub and child is a full package: merge parent's metadata into child and absorb
		// parent.
		mergeExternalReferences(childMeta, parentMeta)
		delete(pkgByID, parent.id)
	}
	// If neither is a stub (both are independent packages with PURLs/CPEs),
	// do not merge metadata between distinct packages to avoid cross-package pollution.
}

// mergeExternalReferences merges the external references from the source metadata into the target
// metadata. If a PURL is found in the source, it is only added if the target does not already have
// a PURL.
func mergeExternalReferences(target *spdxmeta.Metadata, source *spdxmeta.Metadata) {
	for _, srcRef := range source.ExternalReferences {
		if isPURLRef(srcRef) && target.PURL != nil {
			continue
		}
		found := false
		for _, tgtRef := range target.ExternalReferences {
			if tgtRef.Category == srcRef.Category &&
				strings.EqualFold(tgtRef.RefType, srcRef.RefType) &&
				tgtRef.Locator == srcRef.Locator &&
				tgtRef.Comment == srcRef.Comment {
				found = true
				break
			}
		}
		if !found {
			target.ExternalReferences = append(target.ExternalReferences, srcRef)
		}
	}
}

func isPURLRef(ref spdxmeta.ExternalReference) bool {
	return strings.EqualFold(ref.RefType, PURLType) ||
		strings.EqualFold(ref.RefType, "http://spdx.org/rdf/references/purl")
}
