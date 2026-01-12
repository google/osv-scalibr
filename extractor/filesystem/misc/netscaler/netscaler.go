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

// Package netscaler provides an extractor for extracting netscaler version from filesystem artifacts.
package netscaler

import (
	"bufio"
	"context"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

var (
	// Name is the unique identifier for the netscaler extractor.
	Name = "misc/netscaler"
	// Matches filenames like ns-14.1-47.48.gz
	versionFileRegex = regexp.MustCompile(`ns-(\d+\.\d+)-(\d+\.\d+)\.\S+`)
	// Matches version strings like ns-14.1-47.48 in loader.conf content
	versionLoaderRegex = regexp.MustCompile(`ns-(\d+\.\d+)-(\d+\.\d+)`)
	// Matches nsversion content like "NS14.1 Build 21.12"
	versionNsRegex = regexp.MustCompile(`NS(\d+\.\d+) Build (\d+\.\d+)`)
)

// Extractor implements the filesystem.Extractor interface for netscaler.
type Extractor struct{}

// New returns a new NetScaler extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name returns the name of the extractor.
func (e *Extractor) Name() string {
	return Name
}

// Version returns the version of the extractor.
func (e *Extractor) Version() int {
	return 0
}

// Requirements returns the requirements for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired checks if the file is a loader.conf, nsversion, ns.conf
// or matches the netscaler version file pattern (e.g., ns-14.1-47.48.gz).
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Extract the base filename to avoid matching directories
	baseName := strings.ToLower(filepath.Base(api.Path()))

	// Check explicit filenames first
	if baseName == "loader.conf" || baseName == "nsversion" || baseName == "ns.conf" {
		return true
	}

	// Check if the filename starts with "ns-" and contains version string
	if strings.HasPrefix(baseName, "ns-") && versionFileRegex.MatchString(baseName) {
		return true
	}

	return false
}

// Extract returns an Inventory with a package containing NetScaler version, locations where we found them, and the associated filesystem.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var Version string
	var versionLocation string

	baseName := filepath.Base(input.Path)

	// Check for netscaler version in filename. For example, ns-12.1-44.15.gz
	if versionFileRegex.MatchString(baseName) {
		matches := versionFileRegex.FindStringSubmatch(baseName)
		if len(matches) == 3 {
			ver, build := matches[1], matches[2]
			Version = ver + "-" + build
			versionLocation = input.Path
		}
	} else {
		scanner := bufio.NewScanner(input.Reader)

		// Select the appropriate regex once based on the file name.
		// This avoids repeating switch logic or evaluating multiple regexes during scanning.
		var re *regexp.Regexp

		switch strings.ToLower(baseName) {
		case "loader.conf", "ns.conf":
			re = versionLoaderRegex
		case "nsversion":
			re = versionNsRegex
		default:
			// Unknown file type; nothing to extract.
			// For example, ns-12.1.1-45.6.gz
			return inventory.Inventory{}, nil
		}

		// Scan the file line-by-line.
		// Scanner.Scan() reads one line per iteration without loading the entire file into memory.
		for scanner.Scan() {
			if ctx.Err() != nil {
				return inventory.Inventory{}, ctx.Err()
			}

			// Fetch the line
			line := scanner.Text()

			// Try to extract version information using the selected regex.
			matches := re.FindStringSubmatch(line)
			if len(matches) == 3 {
				ver, build := matches[1], matches[2]
				Version = ver + "-" + build
				versionLocation = input.Path
				// Found the version; stop scanning further lines.
				break
			}
		}
	}

	// In case of no findings, return empty inventory.
	if versionLocation == "" {
		return inventory.Inventory{}, nil
	}

	// Initialize empty inventory.
	var inv inventory.Inventory
	// Add findings in a package so detectors can use it later.
	inv.Packages = append(inv.Packages, &extractor.Package{
		Name:      "NetScaler",
		Version:   Version,
		Locations: []string{versionLocation},
		// This is required because the filesystem passed to the detectors
		// is different from the filesystem where we found the artifacts
		// in case of embeddedfs extractors.
		Metadata: input.FS,
	})
	return inv, nil
}
