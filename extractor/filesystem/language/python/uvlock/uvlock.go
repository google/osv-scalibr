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

// Package uvlock extracts uv.lock files.
package uvlock

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/internal/pypipurl"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

type uvLockPackageSource struct {
	Virtual  string `toml:"virtual"`
	Registry string `toml:"registry"`
}

type uvLockPackage struct {
	Name    string              `toml:"name"`
	Version string              `toml:"version"`
	Source  uvLockPackageSource `toml:"source"`

	// uv stores "groups" as a table under "package" after all the packages, which due
	// to how TOML works means it ends up being a property on the last package, even
	// through in this context it's a global property rather than being per-package
	Groups map[string][]uvOptionalDependency `toml:"optional-dependencies"`
}

type uvOptionalDependency struct {
	Name string `toml:"name"`
}
type uvLockFile struct {
	Version  int                               `toml:"version"`
	Packages []uvLockPackage                   `toml:"package"`
	Groups   map[string][]uvOptionalDependency `toml:"package.optional-dependencies"`
}

// Extractor extracts python packages from uv.lock files.
type Extractor struct{}

// Name of the extractor
func (e Extractor) Name() string { return "python/uvlock" }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches uv lockfile patterns
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "uv.lock"
}

// Extract extracts packages from uv.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var parsedLockfile *uvLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return []*extractor.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	packages := make([]*extractor.Inventory, 0, len(parsedLockfile.Packages))

	var groups map[string][]uvOptionalDependency

	// uv stores "groups" as a table under "package" after all the packages, which due
	// to how TOML works means it ends up being a property on the last package, even
	// through in this context it's a global property rather than being per-package
	if len(parsedLockfile.Packages) > 0 {
		groups = parsedLockfile.Packages[len(parsedLockfile.Packages)-1].Groups
	}

	for _, lockPackage := range parsedLockfile.Packages {
		if lockPackage.Source.Virtual == "." {
			continue
		}

		pkgDetails := &extractor.Inventory{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			Locations: []string{input.Path},
			SourceCode: &extractor.SourceCodeIdentifier{
				Commit: "",
			},
		}

		depGroupVals := []string{}

		for group, deps := range groups {
			for _, dep := range deps {
				if dep.Name == lockPackage.Name {
					depGroupVals = append(depGroupVals, group)
				}
			}
		}

		sort.Strings(depGroupVals)

		pkgDetails.Metadata = osv.DepGroupMetadata{
			DepGroupVals: depGroupVals,
		}
		packages = append(packages, pkgDetails)
	}

	return packages, nil
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
