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

// Package packageresolved extracts Package.resolved files
package packageresolved

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "swift/packageresolved"
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will process.
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 10 * units.MiB,
	}
}

// Extractor extracts packages from inside a Package.resolved.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Package.resolved extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired checks if the file is named "Package.resolved".
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if filepath.Base(path) != "Package.resolved" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.stats == nil {
		return
	}
	e.stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract parses and extracts dependency data from a Package.resolved file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(input)
	if e.stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	packages, err := parse(input.Reader)
	if err != nil {
		return nil, err
	}

	var result []*extractor.Package
	for _, pkg := range packages {
		result = append(result, &extractor.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			PURLType: purl.TypeCocoapods,
			Locations: []string{
				input.Path,
			},
		})
	}

	return result, nil
}

// pkg represents a parsed package entry from the Package.resolved file.
type pkg struct {
	Name    string
	Version string
}

// Parse reads and parses a Package.resolved file for package details.
func parse(r io.Reader) ([]pkg, error) {
	var resolvedFile struct {
		Pins []struct {
			Package string `json:"identity"`
			State   struct {
				Version string `json:"version"`
			} `json:"state"`
		} `json:"pins"`
	}

	if err := json.NewDecoder(r).Decode(&resolvedFile); err != nil {
		return nil, fmt.Errorf("failed to parse Package.resolved: %w", err)
	}

	var packages []pkg
	for _, pin := range resolvedFile.Pins {
		packages = append(packages, pkg{
			Name:    pin.Package,
			Version: pin.State.Version,
		})
	}

	return packages, nil
}
