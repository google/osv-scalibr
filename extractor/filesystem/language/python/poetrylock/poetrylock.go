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

// Package poetrylock extracts poetry.lock files.
package poetrylock

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/poetrylock"
)

type poetryLockPackageSource struct {
	Type   string `toml:"type"`
	Commit string `toml:"resolved_reference"`
}

type poetryLockPackage struct {
	Name     string                  `toml:"name"`
	Version  string                  `toml:"version"`
	Optional bool                    `toml:"optional"`
	Groups   []string                `toml:"groups"`
	Source   poetryLockPackageSource `toml:"source"`
}

type poetryLockFile struct {
	Version  int                 `toml:"version"`
	Packages []poetryLockPackage `toml:"package"`
}

// Extractor extracts python packages from poetry.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches poetry lockfile patterns
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "poetry.lock"
}

func resolveGroups(pkg poetryLockPackage) []string {
	// by definition an optional package cannot be in any other group,
	// otherwise that would make it a required package
	if pkg.Optional {
		return []string{"optional"}
	}

	if pkg.Groups == nil {
		return []string{}
	}

	for _, group := range pkg.Groups {
		// the "main" group is the default group used for "production" dependencies,
		// which we represent by an empty slice aka no groups
		if group == "main" {
			return []string{}
		}
	}

	return pkg.Groups
}

// Extract extracts packages from poetry.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *poetryLockFile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		pkgDetails := &extractor.Package{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			PURLType:  purl.TypePyPi,
			Locations: []string{input.Path},
			Metadata: osv.DepGroupMetadata{
				DepGroupVals: resolveGroups(lockPackage),
			},
		}
		if lockPackage.Source.Commit != "" {
			pkgDetails.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: lockPackage.Source.Commit,
			}
		}
		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
