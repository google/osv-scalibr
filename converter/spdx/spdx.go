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

// Package spdx provides utilities for creating SPDX SBOMs.
package spdx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
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
	SPDXDocumentID = "SPDXRef-DOCUMENT"
	// EmptyFileDigest is the hex-encoded sha256 of the empty string.
	EmptyFileDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// spdx_id must only contain letters, numbers, "." and "-"
var spdxIDInvalidCharRe = regexp.MustCompile(`[^a-zA-Z0-9.-]`)

// Config describes custom settings that should be applied to the generated SPDX file.
type Config struct {
	DocumentName      string
	DocumentNamespace string
	Creators          []common.Creator
}

// ToSPDX23 converts the SCALIBR scan results into an SPDX v2.3 document.
func ToSPDX23(i inventory.Inventory, c Config) *v2_3.Document {
	packages := make([]*v2_3.Package, 0, len(i.Packages)+1)

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

	relationships := make([]*v2_3.Relationship, 0, 1+2*len(i.Packages))
	relationships = append(relationships, &v2_3.Relationship{
		RefA:         toDocElementID(SPDXDocumentID),
		RefB:         toDocElementID(mainPackageID),
		Relationship: "DESCRIBES",
	})

	allOtherLicenses := stringset.Set{}
	scalibrToSPDXID := make(map[string]string)
	pkgToSPDXID := make(map[*extractor.Package]string)
	var files []*v2_3.File

	for _, pkg := range i.Packages {
		p := pkg.PURL()
		if p == nil {
			log.Warnf("Package %v has no PURL, skipping", pkg)
			continue
		}

		pName := p.Name
		pVersion := p.Version

		if pName == "" {
			log.Warnf("Package %v PURL name empty, skipping", pkg)
			continue
		}
		id, err := pkg.GetIDOrGenerate()
		if err != nil {
			log.Warnf("Failed to get or generate ID for package %v: %v", pkg, err)
			continue
		}
		pID := fmt.Sprintf("%sPackage-%s-%s", SPDXRefPrefix, replaceSPDXIDInvalidChars(pName), replaceSPDXIDInvalidChars(id))
		scalibrToSPDXID[id] = pID
		if pkg.Name != "" {
			scalibrToSPDXID[pkg.Name] = pID
		}
		pkgToSPDXID[pkg] = pID

		pSourceInfo := getPackageSourceInfo(pkg)

		licensesConcluded, otherLicenses := LicenseExpression(pkg.Licenses)
		allOtherLicenses.Update(otherLicenses)

		packages = append(packages, &v2_3.Package{
			PackageName:           pName,
			PackageSPDXIdentifier: common.ElementID(pID),
			PackageVersion:        pVersion,
			PackageSupplier: &common.Supplier{
				Supplier:     NoAssertion,
				SupplierType: NoAssertion,
			},
			PackageDownloadLocation:   NoAssertion,
			PackageLicenseConcluded:   licensesConcluded,
			PackageLicenseDeclared:    NoAssertion,
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
	}

	packages, files, relationships = addRelationshipsAndNodes(i.Packages, packages, files, relationships, mainPackageID, pkgToSPDXID, scalibrToSPDXID)
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
		Files:         files,
		Relationships: relationships,
		OtherLicenses: ToOtherLicenses(allOtherLicenses),
	}
}

// GetFileSHA256 returns the hex-encoded SHA256 digest of the file at path, relative to rootPath if not absolute.
func GetFileSHA256(path, rootPath string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(rootPath, path)
	}
	if data, err := os.ReadFile(path); err == nil {
		hash := sha256.Sum256(data)
		return hex.EncodeToString(hash[:])
	}
	return EmptyFileDigest
}

func cleanRepoURL(rawURL string) string {
	url := strings.TrimSpace(rawURL)
	url, _, _ = strings.Cut(url, "?")
	url, _, _ = strings.Cut(url, "#")
	if _, after, ok := strings.Cut(url, "://"); ok {
		url = after
	}
	if _, after, ok := strings.Cut(url, "@"); ok {
		url = after
	}
	// Convert SCP host:path to host/path (e.g. github.com:owner/repo -> github.com/owner/repo)
	if host, path, ok := strings.Cut(url, ":"); ok && !strings.Contains(host, "/") {
		url = host + "/" + path
	}
	return strings.TrimSuffix(strings.Trim(url, "/"), ".git")
}

// GetSourceCodePURL returns a PackageURL for the source repository and commit.
func GetSourceCodePURL(repoURL, commit string) *purl.PackageURL {
	url := cleanRepoURL(repoURL)
	if url == "" {
		return nil
	}
	// 1. Handle GitHub repositories: GitHub URLs must be in the format
	// github.com/<owner>/<repo>. Both owner and repo cannot be empty, otherwise return nil.
	if after, ok := strings.CutPrefix(url, "github.com/"); ok {
		if owner, repo, ok := strings.Cut(after, "/"); ok && owner != "" && repo != "" {
			return &purl.PackageURL{
				Type:      purl.TypeGithub,
				Namespace: owner,
				Name:      repo,
				Version:   commit,
			}
		}
		return nil
	}
	// 2. Handle Generic repositories (GoB, GitLab, etc.):
	// Split on the last '/' so leading parts form the namespace, and the trailing part forms the name.
	namespace, name := "", url
	if i := strings.LastIndex(url, "/"); i != -1 {
		namespace, name = url[:i], url[i+1:]
	}
	return &purl.PackageURL{
		Type:      purl.TypeGeneric,
		Namespace: namespace,
		Name:      name,
		Version:   commit,
	}
}

// addRelationshipsAndNodes generates SPDX relationships (CONTAINS, DEPENDS_ON,
// DEPENDENCY_MANIFEST_OF, DESCENDANT_OF) as well as related File nodes and pkg nodes.
func addRelationshipsAndNodes(
	invPackages []*extractor.Package,
	packages []*v2_3.Package,
	files []*v2_3.File,
	relationships []*v2_3.Relationship,
	mainPackageID string,
	pkgToSPDXID map[*extractor.Package]string,
	scalibrToSPDXID map[string]string,
) ([]*v2_3.Package, []*v2_3.File, []*v2_3.Relationship) {
	seenFileSPDXID := make(map[string]bool)
	seenSourceSPDXID := make(map[string]string)

	for _, pkg := range invPackages {
		pID, ok := pkgToSPDXID[pkg]
		if !ok {
			continue
		}
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
		relationships = dependsOn(relationships, pkg, pID, scalibrToSPDXID, mainPackageID)
		files, relationships = dependencyManifestOf(files, relationships, pkg, pID, seenFileSPDXID)
		packages, relationships = descendantOf(packages, relationships, pkg, pID, seenSourceSPDXID)
	}
	return packages, files, relationships
}

// dependsOn appends DEPENDS_ON relationships for each parent ID of pkg.
func dependsOn(
	relationships []*v2_3.Relationship,
	pkg *extractor.Package,
	pID string,
	scalibrToSPDXID map[string]string,
	mainPackageID string,
) []*v2_3.Relationship {
	parentIDs := slices.Sorted(maps.Keys(pkg.ParentIDs))
	for _, parentID := range parentIDs {
		parentSPDXID, ok := parentSPDXID(parentID, scalibrToSPDXID, mainPackageID)
		if !ok {
			log.Warnf("Parent package ID %q for package %v not found in inventory", parentID, pkg)
			continue
		}
		relationships = append(relationships, &v2_3.Relationship{
			RefA:         toDocElementID(parentSPDXID),
			RefB:         toDocElementID(pID),
			Relationship: "DEPENDS_ON",
		})
	}
	return relationships
}

// parentSPDXID resolves a SCALIBR parent ID to an SPDX ID, mapping the
// synthetic "root" parent to the document's main package.
func parentSPDXID(parentID string, scalibrToSPDXID map[string]string, mainPackageID string) (string, bool) {
	if id, ok := scalibrToSPDXID[parentID]; ok {
		return id, true
	}
	if parentID == "root" {
		return mainPackageID, true
	}
	return "", false
}

// dependencyManifestOf appends a File node and a DEPENDENCY_MANIFEST_OF relationship
// for the package's manifest file location, if present.
func dependencyManifestOf(
	files []*v2_3.File,
	relationships []*v2_3.Relationship,
	pkg *extractor.Package,
	pID string,
	seenFileSPDXID map[string]bool,
) ([]*v2_3.File, []*v2_3.Relationship) {
	filePath := pkg.Location.PathOrEmpty()
	if filePath == "" {
		return files, relationships
	}
	pathHash := sha256.Sum256([]byte(filePath))
	fileID := SPDXRefPrefix + "File-" + replaceSPDXIDInvalidChars(filePath) + "-" + hex.EncodeToString(pathHash[:])[:8]
	if !seenFileSPDXID[fileID] {
		seenFileSPDXID[fileID] = true
		files = append(files, &v2_3.File{
			FileName:           filePath,
			FileSPDXIdentifier: common.ElementID(fileID),
			Checksums: []common.Checksum{
				{
					Algorithm: common.SHA256,
					Value:     GetFileSHA256(filePath, pkg.ScanRoot),
				},
			},
			FileCopyrightText: NoAssertion,
		})
	}
	relationships = append(relationships, &v2_3.Relationship{
		RefA:         toDocElementID(fileID),
		RefB:         toDocElementID(pID),
		Relationship: "DEPENDENCY_MANIFEST_OF",
	})
	return files, relationships
}

// descendantOf appends an upstream source Package node and a DESCENDANT_OF relationship
// when pkg represents a local fork with valid SourceCode identifier metadata.
func descendantOf(
	packages []*v2_3.Package,
	relationships []*v2_3.Relationship,
	pkg *extractor.Package,
	pID string,
	seenSourceSPDXID map[string]string,
) ([]*v2_3.Package, []*v2_3.Relationship) {
	if pkg.SourceCode == nil || pkg.SourceCode.Repo == "" || pkg.SourceCode.Commit == "" {
		return packages, relationships
	}
	p := GetSourceCodePURL(pkg.SourceCode.Repo, pkg.SourceCode.Commit)
	if p == nil {
		return packages, relationships
	}
	key := p.String()
	sourceID, exists := seenSourceSPDXID[key]
	if !exists {
		pName := p.Name
		if p.Namespace != "" {
			pName = p.Namespace + "/" + p.Name
		}
		sourceID = fmt.Sprintf("%sPackage-%s-%s", SPDXRefPrefix, replaceSPDXIDInvalidChars(pName), replaceSPDXIDInvalidChars(p.Version))
		seenSourceSPDXID[key] = sourceID
		packages = append(packages, &v2_3.Package{
			PackageName:           pName,
			PackageSPDXIdentifier: common.ElementID(sourceID),
			PackageVersion:        p.Version,
			PackageSupplier: &common.Supplier{
				Supplier:     NoAssertion,
				SupplierType: NoAssertion,
			},
			PackageDownloadLocation:   NoAssertion,
			PackageLicenseConcluded:   NoAssertion,
			PackageLicenseDeclared:    NoAssertion,
			IsFilesAnalyzedTagPresent: false,
			PackageSourceInfo:         getPackageSourceInfo(pkg),
			PackageExternalReferences: []*v2_3.PackageExternalReference{
				{
					Category: "PACKAGE-MANAGER",
					RefType:  "purl",
					Locator:  key,
				},
			},
		})
	}
	relationships = append(relationships, &v2_3.Relationship{
		RefA:         toDocElementID(pID),
		RefB:         toDocElementID(sourceID),
		Relationship: "DESCENDANT_OF",
	})
	return packages, relationships
}

func getPackageSourceInfo(pkg *extractor.Package) string {
	pSourceInfo := ""
	if len(pkg.Plugins) > 0 {
		pSourceInfo = fmt.Sprintf("Identified by the %s extractor", pkg.Plugins[0])
	}
	if pkg.Location.Descriptor != nil && pkg.Location.Descriptor.File != nil && pkg.Location.Descriptor.File.Path != "" {
		pSourceInfo += " from " + pkg.Location.Descriptor.File.Path
	} else {
		locs := []string{}
		for _, l := range pkg.Location.Related {
			if l.File != nil && l.File.Path != "" {
				locs = append(locs, l.File.Path)
			}
		}
		if len(locs) == 1 {
			pSourceInfo += " from " + locs[0]
		} else if len(locs) > 1 {
			pSourceInfo += fmt.Sprintf(" from %d locations, including %s and %s", len(locs), locs[0], locs[1])
		}
	}
	return pSourceInfo
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
