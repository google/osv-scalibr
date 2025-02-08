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
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts software dependencies from an CycloneDX SBOM.
type Extractor struct{}

// Name of the extractor.
func (e Extractor) Name() string { return "sbom/cdx" }

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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var cdxExtractor = findExtractor(input.Path)

	if cdxExtractor == nil {
		return nil, fmt.Errorf("sbom/cdx extractor: Invalid file format %s, only JSON and XML are supported", input.Path)
	}

	cdxBOM, err := cdxExtractor(input.Reader)
	if err != nil {
		return nil, err
	}

	return e.convertCdxBomToInventory(&cdxBOM, input.Path)
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

func (e Extractor) convertCdxBomToInventory(cdxBom *cyclonedx.BOM, path string) ([]*extractor.Inventory, error) {
	results := []*extractor.Inventory{}

	if cdxBom == nil {
		return results, nil
	}

	for _, cdxPkg := range *cdxBom.Components {
		inv := &extractor.Inventory{
			Locations: []string{path},
			Metadata:  &Metadata{},
		}
		m := inv.Metadata.(*Metadata)
		inv.Name = cdxPkg.Name
		inv.Version = cdxPkg.Version
		if cdxPkg.CPE != "" {
			m.CPEs = append(m.CPEs, cdxPkg.CPE)
		}
		if cdxPkg.PackageURL != "" {
			packageURL, err := purl.FromString(cdxPkg.PackageURL)
			if err != nil {
				log.Warnf("Invalid PURL %q for package ref: %q", cdxPkg.PackageURL, cdxPkg.BOMRef)
			} else {
				m.PURL = &packageURL
				if inv.Name == "" {
					inv.Name = packageURL.Name
				}
				if inv.Version == "" {
					inv.Version = packageURL.Version
				}
			}
		}
		inv.Metadata = m
		if m.PURL == nil && len(m.CPEs) == 0 {
			log.Warnf("Neither CPE nor PURL found for package: %+v", cdxPkg)
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
