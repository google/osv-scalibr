// Package aimodels provides AI/ML model inventory extractors.
package aimodels

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor scans Hugging Face model configs for transformers_version.
type Extractor struct{}

// Name returns the unique identifier for this extractor.
func (e Extractor) Name() string {
	return "ai/huggingface-transformers"
}

// Version returns the extractor version number.
func (e Extractor) Version() int {
	return 1
}

// Requirements returns the capabilities required by this extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired determines if the extractor should process the given file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "config.json" || base == "adapter_config.json"
}

// Extract parses the input file and returns an inventory containing the transformers package.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var config struct {
		Version string `json:"transformers_version"`
	}

	// NOTE: We return nil error on JSON decode failure to avoid crashing the scanner
	// when encountering non-HuggingFace config.json files or malformed JSON.
	//nolint:nilerr
	if err := json.NewDecoder(input.Reader).Decode(&config); err != nil {
		return inventory.Inventory{}, nil
	}

	if config.Version == "" {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{
		Packages: []*extractor.Package{{
			Name:     "transformers",
			Version:  config.Version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPath(input.Path),
		}},
	}, nil
}

var _ filesystem.Extractor = Extractor{}
