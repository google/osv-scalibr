//go:build !windows

// Package winget extracts installed packages from Windows Package Manager (Winget) database.
package winget

import (
	"context"
	"errors"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the Winget extractor
const Name = "windows/winget"

// Configuration for the extractor.
type Configuration struct{}

// DefaultConfiguration for the extractor. On non-windows, it contains nothing.
func DefaultConfiguration() Configuration {
	return Configuration{}
}

// Extractor provides a metadata extractor for Winget installed packages.
type Extractor struct{}

// New creates a new Extractor from a given configuration.
func New(config Configuration) standalone.Extractor {
	return &Extractor{}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() standalone.Extractor {
	return New(DefaultConfiguration())
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSWindows}
}

// Extract is a no-op for non-Windows platforms.
func (e *Extractor) Extract(ctx context.Context, input *standalone.ScanInput) (inventory.Inventory, error) {
	return inventory.Inventory{}, errors.New("only supported on Windows")
}