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
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
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

	// Check against the version file regex
	return versionFileRegex.MatchString(baseName)
}

// Extract returns an Inventory with a package containing NetScaler version, locations where we found them, and the associated filesystem.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var Version string
	var versionLocations []string

	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to read %s: %w", input.Path, err)
	}
	contentStr := string(content)

	baseName := filepath.Base(input.Path)

	// Check filename for version
	if versionFileRegex.MatchString(baseName) {
		matches := versionFileRegex.FindStringSubmatch(baseName)
		if len(matches) == 3 {
			ver, build := matches[1], matches[2]
			Version = ver + "-" + build
			versionLocations = append(versionLocations, input.Path)
		}
	}

	switch strings.ToLower(baseName) {
	case "loader.conf":
		lines := strings.Split(contentStr, "\n")
		for _, line := range lines {
			if versionLoaderRegex.MatchString(line) {
				matches := versionLoaderRegex.FindStringSubmatch(line)
				if len(matches) == 3 {
					ver, build := matches[1], matches[2]
					Version = ver + "-" + build
					versionLocations = append(versionLocations, input.Path)
				}
			}
		}
	case "nsversion":
		if versionNsRegex.MatchString(contentStr) {
			matches := versionNsRegex.FindStringSubmatch(contentStr)
			if len(matches) == 3 {
				ver, build := matches[1], matches[2]
				Version = ver + "-" + build
				versionLocations = append(versionLocations, input.Path)
			}
		}
	case "ns.conf":
		lines := strings.Split(contentStr, "\n")
		for _, line := range lines {
			if versionLoaderRegex.MatchString(line) {
				matches := versionLoaderRegex.FindStringSubmatch(line)
				if len(matches) == 3 {
					ver, build := matches[1], matches[2]
					Version = ver + "-" + build
					versionLocations = append(versionLocations, input.Path)
				}
			}
		}
	}

	// In case of no findings, return empty inventory.
	if len(versionLocations) == 0 {
		return inventory.Inventory{}, nil
	}

	// Initialize empty inventory.
	var inv inventory.Inventory
	// Add findings in a package so detectors can use it later.
	inv.Packages = append(inv.Packages, &extractor.Package{
		Name:      "NetScaler",
		Version:   Version,
		PURLType:  purl.TypeNetScaler,
		Locations: versionLocations,
		// This is required because the filesystem passed to the detectors
		// is different from the filesystem where we found the artifacts
		// in case of embeddedfs extractors.
		Metadata: input.FS,
	})
	return inv, nil
}
