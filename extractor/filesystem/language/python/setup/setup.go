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

// Package setup extracts packages from setup.py.
package setup

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
)

const (
	// Name is the unique name of this extractor.
	Name = "python/setup"

	// defaultMaxFileSizeBytes is the maximum file size an extractor will unmarshal.
	// If Extract gets a bigger file, it will return an error.
	defaultMaxFileSizeBytes = 10 * units.MiB
)

// Config is the configuration for the Extractor.
type Config struct {
	// Stats is a stats collector for reporting metrics.
	Stats stats.Collector
	// MaxFileSizeBytes is the maximum file size this extractor will unmarshal. If
	// `FileRequired` gets a bigger file, it will return false,
	MaxFileSizeBytes int64
}

// DefaultConfig returns the default configuration for the setup.py extractor.
func DefaultConfig() Config {
	return Config{
		Stats:            nil,
		MaxFileSizeBytes: defaultMaxFileSizeBytes,
	}
}

// Extractor extracts python packages from setup.py.
type Extractor struct {
	stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a setup.py extractor.
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

// FileRequired returns true if the specified file matches python setup.py file pattern.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()

	if filepath.Base(path) != "setup.py" {
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

// Extract extracts packages from setup.py files passed through the scan input.
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

var packageVersionRe = regexp.MustCompile(`['"]\W?(\w+)\W?(==|>=|<=)\W?([\w.]*)`)

func (e Extractor) extractFromInput(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Package, error) {
	s := bufio.NewScanner(input.Reader)
	packages := []*extractor.Package{}

	for s.Scan() {
		// Return if canceled or exceeding deadline.
		if err := ctx.Err(); err != nil {
			return packages, fmt.Errorf("%s halted at %q because of context error: %w", e.Name(), input.Path, err)
		}

		line := s.Text()
		line = strings.TrimSpace(line)

		// Skip commented lines
		if strings.HasPrefix(line, "#") {
			continue
		}

		matches := packageVersionRe.FindAllStringSubmatch(line, -1)

		for _, match := range matches {
			if len(match) != 4 {
				continue
			}
			if containsTemplate(match[0]) {
				continue
			}

			pkgName := strings.TrimSpace(match[1])
			comp := match[2]
			pkgVersion := strings.TrimSpace(match[3])

			p := &extractor.Package{
				Name:      pkgName,
				Version:   pkgVersion,
				PURLType:  purl.TypePyPi,
				Locations: []string{input.Path},
				Metadata:  &Metadata{VersionComparator: comp},
			}

			packages = append(packages, p)
		}

		if s.Err() != nil {
			return packages, fmt.Errorf("error while scanning setup.py file from %v: %w", input.Path, s.Err())
		}
	}

	return packages, nil
}

func containsTemplate(s string) bool {
	return strings.Contains(s, `%s`) || strings.ContainsAny(s, "%{}")
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
// TODO(b/400910349): Remove and use Package.Ecosystem() directly.
func (e Extractor) Ecosystem(p *extractor.Package) string {
	return p.Ecosystem()
}

// ToPURL converts a package created by this extractor into a PURL.
// TODO(b/400910349): Remove and use Package.PURL() directly.
func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	return p.PURL()
}
