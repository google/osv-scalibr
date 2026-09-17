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
	"path/filepath"
	"regexp"
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
	path := api.Path()

	if filepath.Ext(path) != ".conf" {
		return false
	}

	// The path Cabal package database entries are stored under includes "cabal/store".
	if !strings.Contains(filepath.ToSlash(path), "cabal/store") {
		return false
	}

	// Cabal package database entries are stored directly under a package.db directory.
	if filepath.Base(filepath.Dir(path)) != "package.db" {
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

// dependencyRe will match package names and versions in the following format:
// foo-1.2.3
// foo-bar-1.2.3
// foo-bar-2.0
// foo-bar-1.2.3.4
// foo-bar-1.0rc1
// foo-bar-1.0-alpha.1
var dependencyRe = regexp.MustCompile(`^(.+)-([0-9][A-Za-z0-9.-]*)$`)

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	s := bufio.NewScanner(input.Reader)
	packages := []*extractor.Package{}

	var pkgName string
	var pkgVersion string
	var dependencies []string
	inDepends := false

	for s.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		line := s.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Cabal fields at the top level are not indented.
		isIndented := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')

		if strings.HasPrefix(trimmed, "name:") && !isIndented {
			inDepends = false
			pkgName = strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			continue
		}

		if strings.HasPrefix(trimmed, "version:") && !isIndented {
			inDepends = false
			pkgVersion = strings.TrimSpace(strings.TrimPrefix(trimmed, "version:"))
			continue
		}

		if strings.HasPrefix(trimmed, "depends:") && !isIndented {
			inDepends = true

			depends := strings.TrimSpace(strings.TrimPrefix(trimmed, "depends:"))
			if depends != "" {
				dependencies = append(dependencies, strings.Fields(depends)...)
			}
			continue
		}

		// Handle multiline depends:
		//
		// depends:
		//     base-4.18.2.1
		//     containers-0.6.7.1
		//     text-2.0.2
		if inDepends && isIndented {
			dependencies = append(dependencies, strings.Fields(trimmed)...)
			continue
		}

		// We reached another top-level field.
		inDepends = false
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

	// Packages listed in depends.
	for _, dependency := range dependencies {
		matches := dependencyRe.FindStringSubmatch(dependency)

		// Because FindStringSubmatch() returns the entire match plus each captured group.
		// For instance, when invoked on regex `^(.+)-([0-9][A-Za-z0-9.-]*)$` with "containers-0.6.7.1" argument.
		// 		It returns roughly:
		//			matches[0] = "containers-0.6.7.1" // entire match
		//			matches[1] = "containers"         // first capture group
		//			matches[2] = "0.6.7.1"            // second capture group
		// Thus, length of 3.
		if len(matches) != 3 {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     matches[1],
			Version:  matches[2],
			PURLType: purl.TypeHackage,
			Location: location,
		})
	}

	return packages, nil
}
