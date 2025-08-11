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

// Package cdx extracts software dependencies from an CycloneDX SBOM.
package cdx

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "sbom/cdx"
)

// Extractor extracts software dependencies from an CycloneDX SBOM.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

type extractFunc = func(io.Reader) (cyclonedx.BOM, error)

// https://cyclonedx.org/specification/overview/#recognized-file-patterns
var cdxExtensions = map[string]cyclonedx.BOMFileFormat{
	".cdx.json": cyclonedx.BOMFileFormatJSON,
	".cdx.xml":  cyclonedx.BOMFileFormatXML,
}

var cdxNames = map[string]cyclonedx.BOMFileFormat{
	"bom.json": cyclonedx.BOMFileFormatJSON,
	"bom.xml":  cyclonedx.BOMFileFormatXML,
}

// FileRequired returns true if the specified file is a supported cdx file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return findExtractor(api.Path()) != nil
}

// Extract parses the CycloneDX SBOM and returns a list purls from the SBOM.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var cdxExtractor = findExtractor(input.Path)

	if cdxExtractor == nil {
		return inventory.Inventory{}, errors.New("sbom/cdx extractor: Invalid file format, only JSON and XML are supported")
	}

	cdxBOM, err := cdxExtractor(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	pkgs := e.convertCdxBomToPackage(&cdxBOM, input.Path)
	return inventory.Inventory{Packages: pkgs}, nil
}

func findExtractor(path string) extractFunc {
	// For Windows
	path = filepath.ToSlash(path)

	for ext, format := range cdxExtensions {
		if hasFileExtension(path, ext) {
			return func(rdr io.Reader) (cyclonedx.BOM, error) {
				var cdxBOM cyclonedx.BOM
				return cdxBOM, cyclonedx.NewBOMDecoder(rdr, format).Decode(&cdxBOM)
			}
		}
	}

	for name, format := range cdxNames {
		if strings.ToLower(filepath.Base(path)) == name {
			return func(rdr io.Reader) (cyclonedx.BOM, error) {
				var cdxBOM cyclonedx.BOM
				return cdxBOM, cyclonedx.NewBOMDecoder(rdr, format).Decode(&cdxBOM)
			}
		}
	}

	return nil
}

func enumerateComponents(components []cyclonedx.Component, results *[]*extractor.Package) {
	for _, cdxPkg := range components {
		inv := convertComponentToInventory(cdxPkg)
		if inv != nil {
			*results = append(*results, inv)
		}
		if cdxPkg.Components != nil {
			enumerateComponents(*cdxPkg.Components, results)
		}
	}
}

func (e Extractor) convertCdxBomToPackage(cdxBom *cyclonedx.BOM, path string) []*extractor.Package {
	results := []*extractor.Package{}

	if cdxBom == nil || cdxBom.Components == nil {
		return results
	}

	enumerateComponents(*cdxBom.Components, &results)

	for p := range results {
		results[p].Locations = []string{path}
	}

	return results
}

func convertComponentToInventory(cdxPkg cyclonedx.Component) *extractor.Package {
	pkg := &extractor.Package{
		Metadata: &cdxmeta.Metadata{},
	}
	m := pkg.Metadata.(*cdxmeta.Metadata)
	pkg.Name = cdxPkg.Name
	pkg.Version = cdxPkg.Version
	if cdxPkg.CPE != "" {
		m.CPEs = append(m.CPEs, cdxPkg.CPE)
	}
	if cdxPkg.PackageURL != "" {
		packageURL, err := purl.FromString(cdxPkg.PackageURL)
		if err != nil {
			log.Warnf("Invalid PURL %q for package ref: %q", cdxPkg.PackageURL, cdxPkg.BOMRef)
		} else {
			m.PURL = &packageURL
			pkg.PURLType = packageURL.Type
			if pkg.Name == "" {
				pkg.Name = packageURL.Name
			}
			if pkg.Version == "" {
				pkg.Version = packageURL.Version
			}
		}
	}
	if cdxPkg.Evidence != nil && cdxPkg.Evidence.Occurrences != nil {
		for _, occ := range *cdxPkg.Evidence.Occurrences {
			if occ.Location != "" {
				m.CDXLocations = append(m.CDXLocations, occ.Location)
			}
		}
	}
	pkg.Metadata = m
	if m.PURL == nil && len(m.CPEs) == 0 {
		log.Warnf("Neither CPE nor PURL found for package: %+v", cdxPkg)
		return nil
	}

	return pkg
}

func hasFileExtension(path string, extension string) bool {
	return strings.HasSuffix(strings.ToLower(path), extension)
}
