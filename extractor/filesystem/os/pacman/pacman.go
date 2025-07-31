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

// Package pacman extracts packages from archlinux desc file.
package pacman

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/os/osrelease"
	pacmanmeta "github.com/google/osv-scalibr/extractor/filesystem/os/pacman/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

const (
	// Name is the unique name of this extractor.
	Name = "os/pacman"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 100 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the pacman extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts pacman packages from /var/lib/pacman/local/<package>/desc file.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a pacman extractor.
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

// FileRequired returns true if the specified file matches the "desc" file patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// archPrefix and archSuffix are used to match the right file and location.
	archPrefix := "var/lib/pacman/local/"
	archSuffix := "desc"
	path := api.Path()

	if !strings.HasPrefix(path, archPrefix) || filepath.Base(path) != archSuffix {
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

// Extract extracts packages from "desc" files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := e.extractFromInput(ctx, input)

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

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	m, err := osrelease.GetOSRelease(input.FS)
	if err != nil {
		log.Errorf("osrelease.ParseOsRelease(): %v", err)
	}

	s := bufio.NewScanner(input.Reader)
	var pkgName, pkgVersion, pkgDependencies string
	packages := []*extractor.Package{}

	for s.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		line := s.Text()
		line = strings.TrimSpace(line)

		if len(line) == 0 {
			continue
		}

		if strings.HasPrefix(line, "%NAME%") {
			pkgName, err = extractValue(s)
		} else if strings.HasPrefix(line, "%VERSION%") {
			pkgVersion, err = extractValue(s)
		} else if strings.HasPrefix(line, "%DEPENDS%") {
			pkgDependencies, err = extractValues(s)
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Warnf("Reached EOF for desc file in %v", input.Path)
				break
			}
			return packages, fmt.Errorf("%s halted: %w", e.Name(), err)
		}
	}

	if pkgName != "" && pkgVersion != "" {
		p := &extractor.Package{
			Name:     pkgName,
			Version:  pkgVersion,
			PURLType: purl.TypePacman,
			Metadata: &pacmanmeta.Metadata{
				PackageName:    pkgName,
				PackageVersion: pkgVersion,
				OSID:           m["ID"],
				OSVersionID:    m["VERSION_ID"],
			},
			Locations: []string{input.Path},
		}

		if len(pkgDependencies) != 0 {
			p.Metadata.(*pacmanmeta.Metadata).PackageDependencies = pkgDependencies
		}

		packages = append(packages, p)
	}

	return packages, nil
}

func extractValue(scanner *bufio.Scanner) (string, error) {
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", err
		}

		// EOF
		return "", io.EOF
	}

	return strings.TrimSpace(scanner.Text()), nil
}

func extractValues(scanner *bufio.Scanner) (string, error) {
	var values []string

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}

			// EOF
			return strings.Join(values, ", "), io.EOF
		}

		line := strings.TrimSpace(scanner.Text())

		if len(line) == 0 {
			break
		}

		values = append(values, line)
	}

	return strings.Join(values, ", "), nil
}
