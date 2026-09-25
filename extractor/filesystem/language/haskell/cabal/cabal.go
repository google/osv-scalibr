// Copyright 2026 Google LLC
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

// Package cabal extracts packages installed through cabal package manager.
package cabal

import (
	"bufio"
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "haskell/cabal"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 30 * units.MiB
)

// Extractor extracts cabal package info from cabal installed packages.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a haskell cabal extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSizeBytes := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = cfg.GetMaxFileSizeBytes()
	}

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.HaskellCabalConfig { return c.GetHaskellCabal() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxFileSizeBytes = specific.GetMaxFileSizeBytes()
	}

	return &Extractor{maxFileSizeBytes: maxFileSizeBytes}, nil
}

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the specified file is a cabal store package database conf file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	filePath := api.Path()

	if path.Ext(filePath) != ".conf" {
		return false
	}

	// The path Cabal package database entries are stored under includes "cabal/store".
	if !strings.Contains(filePath, "cabal/store") {
		return false
	}

	// Cabal package database entries are stored directly under a package.db directory.
	if path.Base(path.Dir(filePath)) != "package.db" {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(filePath, fileinfo.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(filePath, fileinfo.Size(), stats.FileRequiredResultOK)
	return true
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts package from the cabal store conf file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)

	if e.Stats != nil {
		var fileSizeBytes int64
		if input.Info != nil {
			fileSizeBytes = input.Info.Size()
		}
		e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
			Path:          input.Path,
			Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
			FileSizeBytes: fileSizeBytes,
		})
	}
	return inventory.Inventory{Packages: pkgs}, err
}

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	s := bufio.NewScanner(input.Reader)
	packages := []*extractor.Package{}

	var pkgName string
	var pkgVersion string

	for s.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		// Stop scanning once both the package name and version have been found.
		if pkgName != "" && pkgVersion != "" {
			break
		}

		line := s.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Cabal fields at the top level are not indented.
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		if strings.HasPrefix(trimmed, "name:") && !isIndented {
			pkgName = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			continue
		}

		if strings.HasPrefix(trimmed, "version:") && !isIndented {
			pkgVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			continue
		}
	}

	if err := s.Err(); err != nil {
		return packages, fmt.Errorf("error while scanning cabal store conf file: %w", err)
	}

	if pkgName == "" || pkgVersion == "" {
		return packages, fmt.Errorf("missing package name or version in cabal store conf file: %s", input.Path)
	}

	location := extractor.LocationFromPath(input.Path)

	// Package represented by this .conf file.
	packages = append(packages, &extractor.Package{
		Name:     pkgName,
		Version:  pkgVersion,
		PURLType: purl.TypeHackage,
		Location: location,
	})

	return packages, nil
}
