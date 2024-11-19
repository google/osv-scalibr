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

// Package spdx extracts software dependencies from an SPDX SBOM.
package spdx

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/rdf"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tagvalue"
	"github.com/spdx/tools-golang/yaml"
)

// Extractor extracts software dependencies from an spdx SBOM.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "sbom/spdx" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

type extractFunc = func(io.Reader) (*spdx.Document, error)

// Format support based on https://spdx.dev/resources/use/#documents
var extensionHandlers = map[string]extractFunc{
	".spdx.json": json.Read,
	".spdx":      tagvalue.Read,
	".spdx.yml":  yaml.Read,
	".spdx.rdf":  rdf.Read,
	// No support for .xsl files because those are too ambiguous and could be many other things.
}

// FileRequired returns true if the specified file is a supported spdx file.
func (e Extractor) FileRequired(path string, _ func() (fs.FileInfo, error)) bool {
	_, isSupported := findExtractor(path)
	return isSupported
}

// Extract parses the SPDX SBOM and returns a list purls from the SBOM.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parseSbom, isSupported = findExtractor(input.Path)

	if !isSupported {
		return nil, fmt.Errorf("sbom/spdx extractor: Invalid file format %s, only JSON, YAML, RDF, and TagValue are supported", input.Path)
	}

	spdxDoc, err := parseSbom(input.Reader)

	if err != nil {
		return nil, err
	}

	return e.convertSpdxDocToInventory(spdxDoc, input.Path)
}

func findExtractor(path string) (extractFunc, bool) {
	// For Windows
	path = filepath.ToSlash(path)

	for key := range extensionHandlers {
		if hasFileExtension(path, key) {
			return extensionHandlers[key], true
		}
	}

	return nil, false
}

func (e Extractor) convertSpdxDocToInventory(spdxDoc *spdx.Document, path string) ([]*extractor.Inventory, error) {
	results := []*extractor.Inventory{}

	for _, spdxPkg := range spdxDoc.Packages {
		inv := &extractor.Inventory{
			Locations: []string{path},
			Metadata:  &Metadata{},
		}
		m := inv.Metadata.(*Metadata)
		for _, extRef := range spdxPkg.PackageExternalReferences {
			// TODO(b/280991231): Support all RefTypes
			if extRef.RefType == "cpe23Type" || extRef.RefType == "http://spdx.org/rdf/references/cpe23Type" {
				m.CPEs = append(m.CPEs, extRef.Locator)
				if len(inv.Name) == 0 {
					inv.Name = extRef.Locator
				}
			} else if extRef.RefType == "purl" || extRef.RefType == "http://spdx.org/rdf/references/purl" {
				if m.PURL != nil {
					log.Warnf("Multiple PURLs found for same package: %q and %q", m.PURL, extRef.Locator)
				}
				packageURL, err := purl.FromString(extRef.Locator)
				inv.Name = packageURL.Name
				if err != nil {
					log.Warnf("Invalid PURL for package: %q", extRef.Locator)
				} else {
					m.PURL = &packageURL
				}
			}
		}
		inv.Metadata = m
		if m.PURL == nil && len(m.CPEs) == 0 {
			log.Warnf("Neither CPE nor PURL found for package: %+v", spdxPkg)
			continue
		}
		results = append(results, inv)
	}

	return results, nil
}

func hasFileExtension(path string, extension string) bool {
	return strings.HasSuffix(strings.ToLower(path), extension)
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return i.Metadata.(*Metadata).PURL
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) string {
	purl := i.Metadata.(*Metadata).PURL
	if purl == nil {
		return ""
	}
	// This is a heuristic. In most cases, the ecosystem _not_ the same as the PURL type.
	return purl.Type
}
