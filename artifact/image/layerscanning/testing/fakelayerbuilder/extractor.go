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

package fakelayerbuilder

import (
	"bufio"
	"context"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts FakeTestLayers built from the FakeLayerBuilder
type FakeTestLayersExtractor struct {
}

// Name of the extractor.
func (e FakeTestLayersExtractor) Name() string { return "fake/layerextractor" }

// Version of the extractor.
func (e FakeTestLayersExtractor) Version() int { return 0 }

// Requirements of the extractor.
func (e FakeTestLayersExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired always returns true, as this is for testing only
func (e FakeTestLayersExtractor) FileRequired(_ filesystem.FileAPI) bool {
	return true
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e FakeTestLayersExtractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	pkgs := []*extractor.Package{}

	for scanner.Scan() {
		pkgline := scanner.Text()
		// If no version found, just return "" as version
		pkg, version, _ := strings.Cut(pkgline, "@")

		pkgs = append(pkgs, &extractor.Package{
			Name:      pkg,
			Version:   version,
			Locations: []string{input.Path},
		})
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, err
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

// ToPURL always returns nil
func (e FakeTestLayersExtractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeGeneric,
		Name:    p.Name,
		Version: p.Version,
	}
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e FakeTestLayersExtractor) ToCPEs(_ *extractor.Package) []string { return []string{} }

// Ecosystem returns no ecosystem as this is a mock for testing
func (e FakeTestLayersExtractor) Ecosystem(p *extractor.Package) string {
	return ""
}

var _ filesystem.Extractor = FakeTestLayersExtractor{}
