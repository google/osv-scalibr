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

// Package packratlock extracts packrat.lock files.
package packratlock

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "r/packratlock"
	// MaxFileSize is the maximum size of a packrat.lock file we will parse (10 MiB).
	MaxFileSize = 10 * 1024 * 1024
)

// Extractor extracts CRAN packages from packrat.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches packrat lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "packrat.lock"
}

// Extract extracts packages from packrat.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input.Info != nil && input.Info.Size() > MaxFileSize {
		return inventory.Inventory{}, fmt.Errorf("%s: file size %d exceeds maximum %d", Name, input.Info.Size(), MaxFileSize)
	}

	scanner := bufio.NewScanner(input.Reader)
	packages := make([]*extractor.Package, 0)

	var currentPackage string
	var currentVersion string
	var currentSource string
	inHeader := true
	validFormat := false

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", Name, err)
		}

		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Blank line separates sections
		if trimmed == "" {
			if !inHeader && currentPackage != "" && currentSource == "CRAN" && currentVersion != "" {
				packages = append(packages, &extractor.Package{
					Name:     currentPackage,
					Version:  currentVersion,
					PURLType: purl.TypeCran,
					Location: extractor.LocationFromPath(input.Path),
				})
			}
			currentPackage = ""
			currentVersion = ""
			currentSource = ""
			inHeader = false
			continue
		}

		// Parse key: value
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:colonIdx])
		value := strings.TrimSpace(trimmed[colonIdx+1:])

		if inHeader && key == "PackratFormat" {
			validFormat = true
		}

		switch key {
		case "Package":
			currentPackage = value
		case "Version":
			currentVersion = value
		case "Source":
			currentSource = value
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	if !validFormat {
		return inventory.Inventory{}, fmt.Errorf("could not extract: not a valid packrat.lock file")
	}

	// Handle last package if file doesn't end with blank line
	if !inHeader && currentPackage != "" && currentSource == "CRAN" && currentVersion != "" {
		packages = append(packages, &extractor.Package{
			Name:     currentPackage,
			Version:  currentVersion,
			PURLType: purl.TypeCran,
			Location: extractor.LocationFromPath(input.Path),
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
