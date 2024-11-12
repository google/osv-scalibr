// Copyright 2024 Google LLC
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

// Package pdmlock extracts pdm.lock files.
package pdmlock

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type pdmLockPackage struct {
	Name     string   `toml:"name"`
	Version  string   `toml:"version"`
	Groups   []string `toml:"groups"`
	Revision string   `toml:"revision"`
}

type pdmLockFile struct {
	Version  string           `toml:"lock-version"`
	Packages []pdmLockPackage `toml:"package"`
}

// Extractor extracts python packages from pdm.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "python/pdmlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches PDM lockfile patterns.
func (e Extractor) FileRequired(path string, _ func() (fs.FileInfo, error)) bool {
	return filepath.Base(path) == "pdm.lock"
}

// Extract extracts packages from pdm.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockFile *pdmLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockFile)
	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	packages := make([]*extractor.Inventory, 0, len(parsedLockFile.Packages))

	for _, pkg := range parsedLockFile.Packages {
		inventory := &extractor.Inventory{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Locations: []string{input.Path},
		}

		depGroups := parseGroupsToDepGroups(pkg.Groups)

		inventory.Metadata = osv.DepGroupMetadata{
			DepGroupVals: depGroups,
		}

		if pkg.Revision != "" {
			inventory.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: pkg.Revision,
			}
		}

		packages = append(packages, inventory)
	}

	return packages, nil
}

// parseGroupsToDepGroups converts pdm lockfile groups to the standard DepGroups
func parseGroupsToDepGroups(groups []string) []string {
	depGroups := []string{}

	var optional = true
	for _, gr := range groups {
		// depGroups can either be:
		// [], [dev], [optional]
		// All packages not in the default group (or the dev group)
		// are optional.
		if gr == "dev" {
			depGroups = append(depGroups, "dev")
			optional = false
		} else if gr == "default" {
			optional = false
		}
	}
	if optional {
		depGroups = append(depGroups, "optional")
	}

	return depGroups
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return pypipurl.MakePackageURL(i)
}

// Ecosystem returns the OSV ecosystem ('PyPI') of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "PyPI"
}

var _ filesystem.Extractor = Extractor{}
