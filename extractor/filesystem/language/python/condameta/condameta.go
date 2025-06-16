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

// Package condameta extracts Conda package metadata from conda-meta JSON files.
package condameta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

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
	Name = "python/condameta"
)

// Config is the configuration for the Extractor.
type Config struct {
	Stats            stats.Collector
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: 10 * units.MiB,
	}
}

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{
		Stats:            e.stats,
		MaxFileSizeBytes: e.maxFileSizeBytes,
	}
}

// Extractor extracts packages from Conda package metadata.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a Conda package metadata extractor.
func New(cfg Config) *Extractor {
	return &Extractor{
		stats:            cfg.Stats,
		maxFileSizeBytes: cfg.MaxFileSizeBytes,
	}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired checks if the file is a valid Conda metadata JSON file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	// Normalize the path to use forward slashes, making it platform-independent
	path = filepath.ToSlash(path)

	// Verify the path contains the `envs/` directory
	if !(strings.HasPrefix(path, "envs/") || strings.Contains(path, "/envs/")) {
		return false
	}

	// Verify extension
	if !strings.HasSuffix(path, ".json") {
		return false
	}

	// Ensure the last directory is `conda-meta`.
	if !strings.HasSuffix(filepath.Dir(path), "conda-meta") {
		return false
	}

	// Check file size if a maximum limit is set.
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

// Extract parses and extracts dependency data from Conda metadata files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkg, err := e.extractFromInput(input)
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
	return inventory.Inventory{Packages: pkg}, err
}

func (e Extractor) extractFromInput(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	// Parse the metadata and get a package
	pkg, err := parse(input.Reader)
	if err != nil {
		return nil, err
	}

	// Return an empty slice if the package name or version is empty
	if pkg.Name == "" || pkg.Version == "" {
		return nil, errors.New("package name or version is empty")
	}

	return []*extractor.Package{&extractor.Package{
		Name:     pkg.Name,
		Version:  pkg.Version,
		PURLType: purl.TypePyPi,
		Locations: []string{
			input.Path,
		},
	}}, nil
}

// parse reads a Conda metadata JSON file and extracts a package.
func parse(r io.Reader) (*condaPackage, error) {
	var pkg condaPackage
	if err := json.NewDecoder(r).Decode(&pkg); err != nil {
		return nil, fmt.Errorf("failed to parse Conda metadata: %w", err)
	}
	return &pkg, nil
}

type condaPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
