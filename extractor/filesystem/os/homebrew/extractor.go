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

// Package homebrew extracts packages from OSX homebrew SPDX SBOM files.
package homebrew

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/spdx/tools-golang/json"
	spdx "github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	caskPath     = "caskroom"
	formuleaPath = "cellar"
	fileName     = "sbom.spdx.json"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 1 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct{}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor extracts software dependencies from a OSX Homebrew SBOM SPDX file
type Extractor struct{}

// New returns a Homebrew extractor.
//
// For most use cases, initialize with:
// ```
// e := New(DefaultConfig())
// ```
func New(cfg Config) *Extractor {
	return &Extractor{}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{}
}

// Name of the extractor.
func (e Extractor) Name() string { return "os/homebrew" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

type extractFunc = func(io.Reader) (*spdx.Document, error)

// Format support based on https://spdx.dev/resources/use/#documents

// FileRequired returns true if the specified file is a supported spdx file.
func (e Extractor) FileRequired(path string, fileinfo fs.FileInfo) bool {
	filePath := strings.ToLower(path)
	filePath = filepath.ToSlash(filePath)

	// Homebrew installs reference paths  /usr/local/Cellar/ and /usr/local/Caskroom
	if !strings.Contains(filePath, formuleaPath) && !strings.Contains(filePath, caskPath) {
		return false
	}

	if !strings.Contains(path, fileName) {
		return false
	}

	return true
}

// Extract parses the HOMEBREW SPDX SBOM JSon and returns a list purls from the SBOM.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parseSbom, isSupported = json.Read, e.FileRequired(input.Path, input.Info)

	if !isSupported {
		return nil, fmt.Errorf("os/homebrew extractor: Invalid file format %s, only JSON sbom.spdx are supported", input.Path)
	}

	spdxDoc, err := parseSbom(input.Reader)

	fmt.Printf("\nemat 1: %s\n", spdxDoc.SPDXVersion)

	if err != nil {
		return nil, err
	}

	return e.convertSpdxDocToInventory(spdxDoc, input.Path)
}

func (e Extractor) convertSpdxDocToInventory(spdxDoc *spdx.Document, path string) ([]*extractor.Inventory, error) {
	results := []*extractor.Inventory{}

	for _, spdxPkg := range spdxDoc.Packages {
		inv := &extractor.Inventory{
			Locations: []string{path},
			Metadata:  &Metadata{},
		}
		m := inv.Metadata.(*Metadata)
		fmt.Printf("\nemat 2: %s\n", spdxDoc.DocumentName)
		for _, extRef := range spdxPkg.PackageExternalReferences {
			fmt.Printf("\nemat 3: %s\n", extRef.RefType)
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
				log.Warnf("\nemat 4:  %+v\n", spdxPkg)
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

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) (*purl.PackageURL, error) {
	return i.Metadata.(*Metadata).PURL, nil
}

// ToCPEs converts an inventory created by this extractor into a list of CPEs.
func (e Extractor) ToCPEs(i *extractor.Inventory) ([]string, error) {
	return i.Metadata.(*Metadata).CPEs, nil
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (Extractor) Ecosystem(i *extractor.Inventory) (string, error) {
	purl := i.Metadata.(*Metadata).PURL
	if purl == nil {
		return "", nil
	}
	return purl.Type, nil
}
