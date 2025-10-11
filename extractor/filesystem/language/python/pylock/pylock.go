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

// Package pylock extracts pylock.toml files
package pylock

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/pylock"
)

type pylockVCS struct {
	Type   string `toml:"type"`
	Commit string `toml:"commit-id"`
}

type pylockDirectory struct {
	Path string `toml:"path"`
}

type pylockPackage struct {
	Name      string          `toml:"name"`
	Version   string          `toml:"version"`
	VCS       pylockVCS       `toml:"vcs"`
	Directory pylockDirectory `toml:"directory"`
}

type pylockLockfile struct {
	Version  string          `toml:"lock-version"`
	Packages []pylockPackage `toml:"packages"`
}

// Extractor extracts python packages from pylock.toml files.
type Extractor struct{}

var _ filesystem.Extractor = Extractor{}

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

// FileRequired returns true if the specified file matches pylock lockfile patterns
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())

	if base == "pylock.toml" {
		return true
	}

	m, _ := filepath.Match("pylock.*.toml", base)

	return m
}

// Extract extracts packages from pylock.toml files passed through the scan input.
func (e Extractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *pylockLockfile

	_, err := toml.NewDecoder(input.Reader).Decode(&parsedLockfile)

	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))

	for _, lockPackage := range parsedLockfile.Packages {
		// this is likely the root package, which is sometimes included in the lockfile
		if lockPackage.Version == "" && lockPackage.Directory.Path == "." {
			continue
		}

		pkgDetails := &extractor.Package{
			Name:      lockPackage.Name,
			Version:   lockPackage.Version,
			PURLType:  purl.TypePyPi,
			Locations: []string{input.Path},
		}
		if lockPackage.VCS.Commit != "" {
			pkgDetails.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: lockPackage.VCS.Commit,
			}
		}
		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

var _ filesystem.Extractor = Extractor{}
