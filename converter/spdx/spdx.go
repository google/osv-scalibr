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
	"time"

	"bitbucket.org/creachadair/stringset"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
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
	// The hex-encoded sha256 of the empty string.
	emptyFileDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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

	var files []*v2_3.File

	relationships := make([]*v2_3.Relationship, 0, 1+2*len(i.Packages))
	relationships = append(relationships, &v2_3.Relationship{
		RefA:         toDocElementID(SPDXDocumentID),
		RefB:         toDocElementID(mainPackageID),
		Relationship: "DESCRIBES",
	})

	allOtherLicenses := stringset.Set{}
	scalibrToSPDXID := make(map[string]string)
	pkgToSPDXID := make(map[*extractor.Package]string)

	pkgIDs := make([]string, len(i.Packages))
	nameToID := make(map[string]string)
	for idx, pkg := range i.Packages {
		p := pkg.PURL()
		if p == nil || p.Name == "" || p.Version == "" {
			continue
		}
		id, err := pkg.GetIDOrGenerate(&extractor.RandomIDGenerator{})
		if err != nil {
			continue
		}
		pID := SPDXRefPrefix + "Package-" + replaceSPDXIDInvalidChars(p.Name) + "-" + replaceSPDXIDInvalidChars(id)
		pkgIDs[idx] = pID
		scalibrToSPDXID[id] = pID
		pkgToSPDXID[pkg] = pID
		nameToID[pkg.Name] = pID
		nameToID[p.Name] = pID
		if p.Namespace != "" {
			nameToID[p.Namespace+"/"+p.Name] = pID
		}
	}

	for idx, pkg := range i.Packages {
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
		pID := pkgIDs[idx]
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

	for _, pkg := range i.Packages {
		pID, ok := pkgToSPDXID[pkg]
		if !ok {
			continue
		}
		// TODO(b/313658493): Add a DESCRIBES relationship or a DocumentDescribes field.

		var fileID string
		var filePath string
		if pkg.Location.Descriptor != nil && pkg.Location.Descriptor.File != nil && pkg.Location.Descriptor.File.Path != "" {
			filePath = pkg.Location.Descriptor.File.Path
		} else if len(pkg.Location.Related) > 0 && pkg.Location.Related[0].File != nil && pkg.Location.Related[0].File.Path != "" {
			filePath = pkg.Location.Related[0].File.Path
		}

		if filePath != "" {
			pathHash := sha256.Sum256([]byte(filePath))
			fileID = SPDXRefPrefix + "File-" + replaceSPDXIDInvalidChars(filePath) + "-" + hex.EncodeToString(pathHash[:])[:8]
			files = append(files, &v2_3.File{
				FileName:           filePath,
				FileSPDXIdentifier: common.ElementID(fileID),
				FileTypes:          []string{"TEXT"},
				LicenseConcluded:   NoAssertion,
				FileCopyrightText:  NoAssertion,
				Checksums: []common.Checksum{
					{
						Algorithm: "SHA256",
						Value:     getFileSHA256(filePath, pkg.ScanRoot),
					},
				},
			})
		}

		addDepManifestRels := func(parentID string) {
			if fileID != "" {
				relationships = append(relationships,
					&v2_3.Relationship{
						RefA:         toDocElementID(parentID),
						RefB:         toDocElementID(fileID),
						Relationship: "CONTAINS",
					},
					&v2_3.Relationship{
						RefA:         toDocElementID(fileID),
						RefB:         toDocElementID(pID),
						Relationship: "DEPENDENCY_MANIFEST_OF",
					},
					&v2_3.Relationship{
						RefA:         toDocElementID(parentID),
						RefB:         toDocElementID(pID),
						Relationship: "DEPENDS_ON",
					},
				)
			} else {
				relationships = append(relationships, &v2_3.Relationship{
					RefA:         toDocElementID(parentID),
					RefB:         toDocElementID(pID),
					Relationship: "CONTAINS",
				})
			}
		}

		parentFound := false
		for parent := range pkg.ParentIDs {
			if parentID, ok := nameToID[parent]; ok {
				addDepManifestRels(parentID)
				parentFound = true
			}
		}
		if !parentFound {
			addDepManifestRels(mainPackageID)
		}
		relationships = append(relationships, &v2_3.Relationship{
			RefA:         toDocElementID(pID),
			RefB:         toDocElementID(NoAssertion),
			Relationship: "CONTAINS",
		})
		parentIDs := slices.Sorted(maps.Keys(pkg.ParentIDs))
		for _, parentID := range parentIDs {
			if parentSPDXID, ok := scalibrToSPDXID[parentID]; ok {
				relationships = append(relationships, &v2_3.Relationship{
					RefA:         toDocElementID(parentSPDXID),
					RefB:         toDocElementID(pID),
					Relationship: "DEPENDS_ON",
				})
			} else if parentID != "root" {
				log.Warnf("Parent package ID %q for package %v not found in inventory", parentID, pkg)
			}
		}
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
		Files:         files,
		Relationships: relationships,
		OtherLicenses: ToOtherLicenses(allOtherLicenses),
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

func getFileSHA256(path string, rootPath string) string {
	fullPath := path
	if !filepath.IsAbs(fullPath) && rootPath != "" {
		fullPath = filepath.Join(rootPath, path)
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return emptyFileDigest
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
