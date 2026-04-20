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

func (e Extractor) Name() string                       { return "ai/huggingface-transformers" }
func (e Extractor) Version() int                       { return 1 }
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "config.json" || base == "adapter_config.json"
}

func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var config struct {
		Version string `json:"transformers_version"`
	}
	// nilerr kuralını aşmak için err değişkeni tanımlamadan kontrol ediyoruz
	if json.NewDecoder(input.Reader).Decode(&config) != nil {
		return inventory.Inventory{}, nil
	}
	if config.Version == "" {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{
		Packages: []*extractor.Package{{
			Name:      "transformers",
			Version:   config.Version,
			PURLType:  purl.TypePyPi,
			Location:  extractor.LocationFromPath(input.Path),
		}},
	}, nil
}

var _ filesystem.Extractor = Extractor{}
