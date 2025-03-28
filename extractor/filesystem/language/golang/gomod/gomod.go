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

// Package gomod extracts go.mod files.
package gomod

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/exp/maps"
	"golang.org/x/mod/modfile"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/gomod"
)

// Extractor extracts go packages from a go.mod file,
// including the stdlib version by using the top level go version
//
// The output is not sorted and will not be in a consistent order
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches go.mod files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "go.mod"
}

// Extract extracts packages from a go.mod file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read %s: %w", input.Path, err)
	}
	parsedLockfile, err := modfile.Parse(input.Path, b, nil)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	// Store the packages in a map since they might be overwritten by later entries.
	type mapKey struct {
		name    string
		version string
	}
	packages := map[mapKey]*extractor.Package{}

	for _, require := range parsedLockfile.Require {
		name := require.Mod.Path
		version := strings.TrimPrefix(require.Mod.Version, "v")
		packages[mapKey{name: name, version: version}] = &extractor.Package{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
		}
	}

	// Apply go.mod replace directives to the identified packages by updating their
	// names+versions as instructed by the directive.
	for _, replace := range parsedLockfile.Replace {
		var replacements []mapKey

		if replace.Old.Version == "" {
			// If the version to replace is omitted, all versions of the module are replaced.
			for k, pkg := range packages {
				if pkg.Name == replace.Old.Path {
					replacements = append(replacements, k)
				}
			}
		} else {
			// If the version to replace is specified only that specific version of the
			// module is replaced.
			s := mapKey{name: replace.Old.Path, version: strings.TrimPrefix(replace.Old.Version, "v")}

			// A `replace` directive has no effect if the name or version to replace is not present.
			if _, ok := packages[s]; ok {
				replacements = []mapKey{s}
			}
		}

		for _, replacement := range replacements {
			packages[replacement] = &extractor.Package{
				Name:      replace.New.Path,
				Version:   strings.TrimPrefix(replace.New.Version, "v"),
				Locations: []string{input.Path},
			}
		}
	}

	// Add the Go stdlib as an explicit dependency.
	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		packages[mapKey{name: "stdlib"}] = &extractor.Package{
			Name:      "stdlib",
			Version:   parsedLockfile.Go.Version,
			Locations: []string{input.Path},
		}
	}

	// Give the toolchain version priority, if present
	if parsedLockfile.Toolchain != nil && parsedLockfile.Toolchain.Name != "" {
		version, _, _ := strings.Cut(parsedLockfile.Toolchain.Name, "-")

		packages[mapKey{name: "stdlib"}] = &extractor.Package{
			Name:      "stdlib",
			Version:   strings.TrimPrefix(version, "go"),
			Locations: []string{input.Path},
		}
	}

	// The map values might have changed after replacement so we need to run another
	// deduplication pass.
	dedupedPs := map[mapKey]*extractor.Package{}
	for _, p := range packages {
		dedupedPs[mapKey{name: p.Name, version: p.Version}] = p
	}
	return inventory.Inventory{Packages: maps.Values(dedupedPs)}, nil
}

// ToPURL converts a package created by this extractor into a PURL.
func (e Extractor) ToPURL(p *extractor.Package) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeGolang,
		Name:    p.Name,
		Version: p.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(p *extractor.Package) string {
	return "Go"
}

var _ filesystem.Extractor = Extractor{}
