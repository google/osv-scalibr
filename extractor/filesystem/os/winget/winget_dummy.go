//go:build !windows

// Package winget extracts installed packages from Windows Package Manager (Winget) database.
package winget

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the Winget extractor
const Name = "os/winget"

// Extractor provides a metadata extractor for Winget installed packages.
type Extractor struct{}

// New creates a new Extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor {
	return New()
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// FileRequired returns false on non-Windows platforms since Winget databases don't exist
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return false
}

// Extract is a no-op for non-Windows platforms.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("only supported on Windows")
}
