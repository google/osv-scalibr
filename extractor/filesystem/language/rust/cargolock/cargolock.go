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

// Package cargolock extracts Cargo.lock files for rust projects
package cargolock

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "rust/cargolock"
)

type cargoLockPackage struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
}

type cargoLockFile struct {
	Version  int                `toml:"version"`
	Packages []cargoLockPackage `toml:"package"`
}

// Extractor extracts crates.io packages from Cargo.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// FileRequired returns true if the specified file matches Cargo lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "Cargo.lock"
}

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// Extract extracts packages from Cargo.lock files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *cargoLockFile

	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	_, err = toml.NewDecoder(bytes.NewReader(b)).Decode(&parsedLockfile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	lineNumbers := findCargoLockLines(b)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		loc := extractor.LocationFromPath(input.Path)
		key := lockPackage.Name + ":" + lockPackage.Version
		if line, ok := lineNumbers[key]; ok && line > 0 {
			loc = extractor.LocationFromPathAndLine(input.Path, line)
		}
		packages = append(packages, &extractor.Package{
			Name:     lockPackage.Name,
			Version:  lockPackage.Version,
			PURLType: purl.TypeCargo,
			Location: loc,
		})
	}

	return inventory.Inventory{Packages: packages}, nil
}

func findCargoLockLines(content []byte) map[string]int {
	lines := make(map[string]int)
	rawLines := bytes.Split(content, []byte("\n"))

	type pkgInfo struct {
		name    string
		version string
		line    int
	}

	var currentPkg *pkgInfo

	for i, rawLine := range rawLines {
		lineNum := i + 1
		line := strings.TrimSpace(string(rawLine))

		if line == "[[package]]" {
			if currentPkg != nil && currentPkg.name != "" {
				key := currentPkg.name + ":" + currentPkg.version
				if lines[key] == 0 {
					lines[key] = currentPkg.line
				}
			}
			currentPkg = &pkgInfo{line: lineNum}
		} else if strings.HasPrefix(line, "[") {
			if currentPkg != nil && currentPkg.name != "" {
				key := currentPkg.name + ":" + currentPkg.version
				if lines[key] == 0 {
					lines[key] = currentPkg.line
				}
			}
			currentPkg = nil
		} else if currentPkg != nil {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
				if k == "name" {
					currentPkg.name = v
					currentPkg.line = lineNum
				} else if k == "version" {
					currentPkg.version = v
				}
			}
		}
	}
	if currentPkg != nil && currentPkg.name != "" {
		key := currentPkg.name + ":" + currentPkg.version
		if lines[key] == 0 {
			lines[key] = currentPkg.line
		}
	}

	return lines
}

var _ filesystem.Extractor = Extractor{}
