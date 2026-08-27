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

package spdx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

// Config3 describes custom settings that should be applied to the generated SPDX 3.0 document.
type Config3 struct {
	DocumentName      string
	DocumentNamespace string
	Creators          []common.Creator
}

// builder3 accumulates the graph elements of a single SPDX 3.0 document. Elements are kept in
// per-kind slices so that the final graph has a deterministic order regardless of the order the
// inventory is walked in.
type builder3 struct {
	namespace string

	agents        []any
	licenses      []any
	packages      []any
	files         []any
	relationships []any

	licenseIRIs      map[string]string
	seenFileIRI      map[string]bool
	seenSourceIRI    map[string]string
	allOtherLicenses stringset.Set
	relCount         int
}

// ToSPDX30 converts the SCALIBR scan results into an SPDX v3.0.1 JSON-LD document.
func ToSPDX30(i inventory.Inventory, c Config3) *Document3 {
	namespace := c.DocumentNamespace
	if namespace == "" {
		namespace = "https://spdx.google/" + uuid.New().String()
	}
	name := c.DocumentName
	if name == "" {
		name = "SCALIBR-generated SPDX"
	}

	b := &builder3{
		namespace:        namespace,
		licenseIRIs:      make(map[string]string),
		seenFileIRI:      make(map[string]bool),
		seenSourceIRI:    make(map[string]string),
		allOtherLicenses: stringset.Set{},
	}

	creationInfo := b.addCreators(c.Creators)

	mainPackageIRI := b.iri(SPDXRefPrefix + "Package-main-" + uuid.New().String())
	b.packages = append(b.packages, &Package3{
		Element3:       b.elementForIRI(mainPackageIRI, TypePackage, "main"),
		PackageVersion: "0",
	})

	documentIRI := b.iri(SPDXDocumentID)
	document := &SpdxDocument3{
		Element3:           b.elementForIRI(documentIRI, TypeSpdxDocument, name),
		DataLicense:        b.licenseExpressionIRI("CC0-1.0", stringset.Set{}),
		RootElement:        []string{mainPackageIRI},
		ProfileConformance: []string{"core", "software"},
	}
	b.addRelationship(documentIRI, RelDescribes, mainPackageIRI)

	scalibrToIRI := make(map[string]string)
	pkgToIRI := make(map[*extractor.Package]string)

	for _, pkg := range i.Packages {
		p := pkg.PURL()
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
		id, err := pkg.GetIDOrGenerate()
		if err != nil {
			log.Warnf("Failed to get or generate ID for package %v: %v", pkg, err)
			continue
		}
		pIRI := b.iri(fmt.Sprintf("%sPackage-%s-%s", SPDXRefPrefix, replaceSPDXIDInvalidChars(pName), replaceSPDXIDInvalidChars(id)))
		scalibrToIRI[id] = pIRI
		if pkg.Name != "" {
			scalibrToIRI[pkg.Name] = pIRI
		}
		pkgToIRI[pkg] = pIRI

		e := b.elementForIRI(pIRI, TypePackage, pName)
		e.ExternalIdentifier = []ExternalIdentifier3{purlIdentifier(p.String())}
		b.packages = append(b.packages, &Package3{
			Element3:       e,
			PackageVersion: pVersion,
			PackageURL:     p.String(),
			SourceInfo:     getPackageSourceInfo(pkg),
		})

		licensesConcluded, otherLicenses := LicenseExpression(pkg.Licenses)
		b.allOtherLicenses.Update(otherLicenses)
		b.addRelationship(pIRI, RelHasConcludedLicense, b.licenseExpressionIRI(licensesConcluded, otherLicenses))
	}

	b.addRelationshipsAndNodes(i.Packages, mainPackageIRI, pkgToIRI, scalibrToIRI)
	b.addCustomLicenses()

	graph := make([]any, 0, 2+len(b.agents)+len(b.licenses)+len(b.packages)+len(b.files)+len(b.relationships))
	graph = append(graph, creationInfo, document)
	graph = append(graph, b.agents...)
	graph = append(graph, b.licenses...)
	graph = append(graph, b.packages...)
	graph = append(graph, b.files...)
	graph = append(graph, b.relationships...)

	return &Document3{Context: SPDX3Context, Graph: graph}
}

func (b *builder3) iri(localID string) string {
	return b.namespace + "/" + localID
}

func (b *builder3) elementForIRI(iri, typ, name string) Element3 {
	return Element3{
		SPDXID:       iri,
		Type:         typ,
		Name:         name,
		CreationInfo: creationInfoID,
	}
}

func (b *builder3) element(localID, typ, name string) Element3 {
	return b.elementForIRI(b.iri(localID), typ, name)
}

func (b *builder3) addRelationship(from, relType string, to ...string) {
	b.relCount++
	b.relationships = append(b.relationships, &Relationship3{
		Element3:         b.element(fmt.Sprintf("%sRelationship-%d", SPDXRefPrefix, b.relCount), TypeRelationship, ""),
		From:             from,
		To:               to,
		RelationshipType: relType,
	})
}

// addCreators emits an Agent element per creator and returns the CreationInfo they belong to.
// SCALIBR is always listed as a SoftwareAgent in createdBy, which also guarantees the spec's
// requirement of at least one creating Agent when the caller only passes tools.
func (b *builder3) addCreators(creators []common.Creator) *CreationInfo3 {
	scalibrIRI := b.iri(SPDXRefPrefix + "Agent-SCALIBR")
	b.agents = append(b.agents, &Element3{
		SPDXID:       scalibrIRI,
		Type:         TypeSoftwareAgent,
		Name:         "SCALIBR",
		CreationInfo: creationInfoID,
	})

	createdBy := []string{scalibrIRI}
	var createdUsing []string
	for i, cr := range creators {
		typ := TypePerson
		switch cr.CreatorType {
		case "Organization":
			typ = TypeOrganization
		case "Tool":
			typ = TypeTool
		}
		iri := b.iri(fmt.Sprintf("%sAgent-%d-%s", SPDXRefPrefix, i, replaceSPDXIDInvalidChars(cr.Creator)))
		b.agents = append(b.agents, &Element3{
			SPDXID:       iri,
			Type:         typ,
			Name:         cr.Creator,
			CreationInfo: creationInfoID,
		})
		if typ == TypeTool {
			createdUsing = append(createdUsing, iri)
		} else {
			createdBy = append(createdBy, iri)
		}
	}

	return &CreationInfo3{
		ID:           creationInfoID,
		Type:         TypeCreationInfo,
		SpecVersion:  SPDX3Version,
		Created:      time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		CreatedBy:    createdBy,
		CreatedUsing: createdUsing,
	}
}

// licenseExpressionIRI returns the IRI of the LicenseExpression element for expr, creating it on
// first use so that identical expressions are shared across packages. customLicenses holds the
// texts of the non-SPDX licenses referenced by expr, which are mapped to the IRIs of the
// CustomLicense elements addCustomLicenses will emit for them.
func (b *builder3) licenseExpressionIRI(expr string, customLicenses stringset.Set) string {
	if iri, ok := b.licenseIRIs[expr]; ok {
		return iri
	}
	iri := b.iri(SPDXRefPrefix + "LicenseExpression-" + replaceSPDXIDInvalidChars(expr))
	b.licenseIRIs[expr] = iri
	var customIDToURI []DictionaryEntry3
	for _, l := range customLicenses.Elements() {
		ref := spdxLicenceRef(l)
		customIDToURI = append(customIDToURI, DictionaryEntry3{
			Type:  TypeDictionaryEntry,
			Key:   ref,
			Value: b.iri(ref),
		})
	}
	b.licenses = append(b.licenses, &LicenseExpression3{
		Element3:          b.elementForIRI(iri, TypeLicenseExpression, ""),
		LicenseExpression: expr,
		CustomIDToURI:     customIDToURI,
	})
	return iri
}

// addCustomLicenses emits a CustomLicense element per non-SPDX license text collected while
// building the packages. This is the SPDX 3.0 equivalent of 2.3's document level OtherLicenses.
func (b *builder3) addCustomLicenses() {
	for _, l := range b.allOtherLicenses.Elements() {
		ref := spdxLicenceRef(l)
		b.licenses = append(b.licenses, &CustomLicense3{
			Element3:    b.element(ref, TypeCustomLicense, ref),
			LicenseText: l,
		})
	}
}

// addRelationshipsAndNodes generates the contains, dependsOn, hasDependencyManifest and
// descendantOf edges along with the File and upstream Package nodes they point at.
func (b *builder3) addRelationshipsAndNodes(
	invPackages []*extractor.Package,
	mainPackageIRI string,
	pkgToIRI map[*extractor.Package]string,
	scalibrToIRI map[string]string,
) {
	for _, pkg := range invPackages {
		pIRI, ok := pkgToIRI[pkg]
		if !ok {
			continue
		}
		b.addRelationship(mainPackageIRI, RelContains, pIRI)
		b.dependsOn(pkg, pIRI, scalibrToIRI)
		b.hasDependencyManifest(pkg, pIRI)
		b.descendantOf(pkg, pIRI)
	}
}

func (b *builder3) dependsOn(pkg *extractor.Package, pIRI string, scalibrToIRI map[string]string) {
	for _, parentID := range slices.Sorted(maps.Keys(pkg.ParentIDs)) {
		if parentIRI, ok := scalibrToIRI[parentID]; ok {
			b.addRelationship(parentIRI, RelDependsOn, pIRI)
		} else if parentID != "root" {
			log.Warnf("Parent package ID %q for package %v not found in inventory", parentID, pkg)
		}
	}
}

// hasDependencyManifest appends a File node and the edge from the package to it. Note the direction
// is the reverse of 2.3's DEPENDENCY_MANIFEST_OF.
func (b *builder3) hasDependencyManifest(pkg *extractor.Package, pIRI string) {
	filePath := pkg.Location.PathOrEmpty()
	if filePath == "" {
		return
	}
	pathHash := sha256.Sum256([]byte(filePath))
	fileIRI := b.iri(SPDXRefPrefix + "File-" + replaceSPDXIDInvalidChars(filePath) + "-" + hex.EncodeToString(pathHash[:])[:8])
	if !b.seenFileIRI[fileIRI] {
		b.seenFileIRI[fileIRI] = true
		e := b.elementForIRI(fileIRI, TypeFile, filePath)
		e.VerifiedUsing = []Hash3{{
			Type:      TypeHash,
			Algorithm: "sha256",
			HashValue: GetFileSHA256(filePath, pkg.ScanRoot),
		}}
		b.files = append(b.files, &File3{Element3: e, CopyrightText: NoAssertion})
	}
	b.addRelationship(pIRI, RelHasDependencyManifest, fileIRI)
}

// descendantOf appends an upstream source Package node and the edge to it when pkg represents a
// local fork with valid SourceCode identifier metadata.
func (b *builder3) descendantOf(pkg *extractor.Package, pIRI string) {
	if pkg.SourceCode == nil || pkg.SourceCode.Repo == "" || pkg.SourceCode.Commit == "" {
		return
	}
	p := GetSourceCodePURL(pkg.SourceCode.Repo, pkg.SourceCode.Commit)
	if p == nil {
		return
	}
	key := p.String()
	sourceIRI, exists := b.seenSourceIRI[key]
	if !exists {
		pName := p.Name
		if p.Namespace != "" {
			pName = p.Namespace + "/" + p.Name
		}
		sourceIRI = b.iri(fmt.Sprintf("%sPackage-%s-%s", SPDXRefPrefix, replaceSPDXIDInvalidChars(pName), replaceSPDXIDInvalidChars(p.Version)))
		b.seenSourceIRI[key] = sourceIRI
		e := b.elementForIRI(sourceIRI, TypePackage, pName)
		e.ExternalIdentifier = []ExternalIdentifier3{purlIdentifier(key)}
		b.packages = append(b.packages, &Package3{
			Element3:       e,
			PackageVersion: p.Version,
			PackageURL:     key,
			SourceInfo:     getPackageSourceInfo(pkg),
		})
	}
	b.addRelationship(pIRI, RelDescendantOf, sourceIRI)
}

func purlIdentifier(p string) ExternalIdentifier3 {
	return ExternalIdentifier3{
		Type:                   TypeExternalIdentifier,
		ExternalIdentifierType: "packageUrl",
		Identifier:             p,
	}
}
