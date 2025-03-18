package fakelayerbuilder

import (
	"bufio"
	"context"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
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
func (e FakeTestLayersExtractor) Extract(_ context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	invs := []*extractor.Inventory{}

	for scanner.Scan() {
		pkgline := scanner.Text()
		// If no version found, just return "" as version
		pkg, version, _ := strings.Cut(pkgline, "@")

		invs = append(invs, &extractor.Inventory{
			Name:      pkg,
			Version:   version,
			Locations: []string{input.Path},
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return invs, nil
}

// ToPURL always returns nil
func (e FakeTestLayersExtractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeGeneric,
		Name:    i.Name,
		Version: i.Version,
	}
}

// ToCPEs is not applicable as this extractor does not infer CPEs from the Inventory.
func (e FakeTestLayersExtractor) ToCPEs(_ *extractor.Inventory) []string { return []string{} }

// Ecosystem returns no ecosystem as this is a mock for testing
func (e FakeTestLayersExtractor) Ecosystem(i *extractor.Inventory) string {
	return ""
}

var _ filesystem.Extractor = FakeTestLayersExtractor{}
