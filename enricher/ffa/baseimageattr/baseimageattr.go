// Package baseimageattr enriches packages from unknown binaries extractor with potential base images from deps.dev.
package baseimageattr

import (
	"context"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name of the base image attribution enricher.
	Name = "ffa/baseimageattr"
)

// Enricher enriches the inventory by filtering out packages that are accounted for in a base image.
type Enricher struct {
}

// New returns a new Enricher.
func New(_ *cpb.PluginConfig) (enricher.Enricher, error) {
	return &Enricher{}, nil
}

// Name of the base image attribution enricher.
func (*Enricher) Name() string { return Name }

// Version of the base image attribution enricher.
func (*Enricher) Version() int { return 0 }

// Requirements of the base image attribution enricher.
func (*Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

// RequiredPlugins returns a list of Plugins that need to be enabled for this Enricher to work.
func (*Enricher) RequiredPlugins() []string {
	return []string{unknownbinariesextr.Name, baseimage.Name}
}

// Enrich filters packages from unknown binaries extractor that can be attributed to a base image.
func (e *Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	inv.Packages = slices.DeleteFunc(inv.Packages, isAttributedToBaseImage)
	return nil
}

// isAttributedToBaseImage returns true if the package is accounted for in a base image.
func isAttributedToBaseImage(pkg *extractor.Package) bool {
	// Packages that are not extracted by unknown binaries extractor should be kept
	if !slices.Contains(pkg.Plugins, unknownbinariesextr.Name) {
		return false
	}
	// Packages that does not have layer metadata cannot be attributed and should be kept
	if pkg.LayerMetadata == nil {
		return false
	}
	// Packages that does not have a match for base image from base image enricher should be kept
	if pkg.LayerMetadata.BaseImageIndex == 0 {
		return false
	}
	return true
}
