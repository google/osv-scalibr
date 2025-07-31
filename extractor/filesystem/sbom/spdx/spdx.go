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
)

const (
	// Name is the unique name of this extractor.
	Name = "sbom/spdx"
)

// Extractor extracts software dependencies from an spdx SBOM.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

type extractFunc = func(io.Reader) (*spdx.Document, error)

// Format support based on https://spdx.dev/resources/use/#documents
var extensionHandlers = map[string]extractFunc{
	".spdx.json":    json.Read,
	".spdx":         tagvalue.Read,
	".spdx.yml":     yaml.Read,
	".spdx.rdf":     rdf.Read,
	".spdx.rdf.xml": rdf.Read,
	// No support for .xsl files because those are too ambiguous and could be many other things.
}

// FileRequired returns true if the specified file is a supported spdx file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	_, isSupported := findExtractor(api.Path())
	return isSupported
}

// Extract parses the SPDX SBOM and returns a list purls from the SBOM.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parseSbom, isSupported = findExtractor(input.Path)

	if !isSupported {
		return inventory.Inventory{}, errors.New("sbom/spdx extractor: Invalid file format, only JSON, YAML, RDF, and TagValue are supported")
	}

	spdxDoc, err := parseSbom(input.Reader)

	if err != nil {
		return inventory.Inventory{}, err
	}

	pkgs := e.convertSpdxDocToPackage(spdxDoc, input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
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

func (e Extractor) convertSpdxDocToPackage(spdxDoc *spdx.Document, path string) []*extractor.Package {
	results := []*extractor.Package{}

	for _, spdxPkg := range spdxDoc.Packages {
		pkg := &extractor.Package{
			Locations: []string{path},
			Metadata:  &spdxmeta.Metadata{},
		}
		m := pkg.Metadata.(*spdxmeta.Metadata)
		for _, extRef := range spdxPkg.PackageExternalReferences {
			// TODO(b/280991231): Support all RefTypes
			if extRef.RefType == "cpe23Type" || extRef.RefType == "http://spdx.org/rdf/references/cpe23Type" {
				m.CPEs = append(m.CPEs, extRef.Locator)
				if len(pkg.Name) == 0 {
					pkg.Name = extRef.Locator
				}
			} else if extRef.RefType == "purl" || extRef.RefType == "http://spdx.org/rdf/references/purl" {
				if m.PURL != nil {
					log.Warnf("Multiple PURLs found for same package: %q and %q", m.PURL, extRef.Locator)
				}
				packageURL, err := purl.FromString(extRef.Locator)
				pkg.Name = packageURL.Name
				if err != nil {
					log.Warnf("Invalid PURL %q for package: %q", extRef.Locator, spdxPkg.PackageName)
				} else {
					m.PURL = &packageURL
					pkg.PURLType = packageURL.Type
				}
			}
		}
		pkg.Metadata = m
		if m.PURL == nil && len(m.CPEs) == 0 {
			log.Warnf("Neither CPE nor PURL found for package: %+v", spdxPkg)
			continue
		}
		results = append(results, pkg)
	}

	return results
}

func hasFileExtension(path string, extension string) bool {
	return strings.HasSuffix(strings.ToLower(path), extension)
}
