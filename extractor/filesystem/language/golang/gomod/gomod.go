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
	"go/version"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/log"
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
//
// go.sum is not considered since the 'go.mod' file
// is necessary to determine the Go version before opening it.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "go.mod"
}

type goVersion = string

type ivKey struct {
	name    string
	version string
}

// Extract extracts packages from a go.mod file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	ivs, goVersion, err := e.extractGoMod(input)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	// At go 1.17 and above, the go command adds an indirect requirement for each module that provides any
	// package imported (even indirectly) by a package or test in the main module or passed as an argument to go get.
	if goVersion == "" || version.Compare("go"+goVersion, "go1.17") >= 0 {
		return maps.Values(ivs), nil
	}

	// For versions below 1.17 extract indirect dependencies from the go.sum file
	sumIvs, err := extractFromSum(input)
	if err != nil {
		log.Warnf("could not extract from %s's sum file: %w", input.Path, err)
		return maps.Values(ivs), nil
	}

	// merge go.sum inventories with go.mod ones
	for k, sumIv := range sumIvs {
		if iv, ok := ivs[k]; ok {
			// if the dependency is already present then add `go.sum` to its Locations slice
			iv.Locations = append(iv.Locations, sumIv.Locations...)
		} else {
			// otherwise add a new dependency to the inventory
			ivs[k] = sumIv
		}
	}

	return maps.Values(ivs), nil
}

func (e Extractor) extractGoMod(input *filesystem.ScanInput) (map[ivKey]*extractor.Inventory, goVersion, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, "", err
	}
	parsedLockfile, err := modfile.Parse(input.Path, b, nil)
	if err != nil {
		return nil, "", err
	}

	// Store the packages in a map since they might be overwritten by later entries.
	packages := map[ivKey]*extractor.Inventory{}

	for _, require := range parsedLockfile.Require {
		name := require.Mod.Path
		version := strings.TrimPrefix(require.Mod.Version, "v")
		packages[ivKey{name: name, version: version}] = &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{input.Path},
		}
	}

	// Apply go.mod replace directives to the identified packages by updating their
	// names+versions as instructed by the directive.
	for _, replace := range parsedLockfile.Replace {
		var replacements []ivKey

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
			s := ivKey{name: replace.Old.Path, version: strings.TrimPrefix(replace.Old.Version, "v")}

			// A `replace` directive has no effect if the name or version to replace is not present.
			if _, ok := packages[s]; ok {
				replacements = []ivKey{s}
			}
		}

		for _, replacement := range replacements {
			packages[replacement] = &extractor.Inventory{
				Name:      replace.New.Path,
				Version:   strings.TrimPrefix(replace.New.Version, "v"),
				Locations: []string{input.Path},
			}
		}
	}

	goVersion := ""
	if parsedLockfile.Go != nil && parsedLockfile.Go.Version != "" {
		goVersion = parsedLockfile.Go.Version
	}

	// Give the toolchain version priority, if present
	if parsedLockfile.Toolchain != nil && parsedLockfile.Toolchain.Name != "" {
		version, _, _ := strings.Cut(parsedLockfile.Toolchain.Name, "-")
		goVersion = strings.TrimPrefix(version, "go")
	}

	// Add the Go stdlib as an explicit dependency.
	if goVersion != "" {
		packages[ivKey{name: "stdlib"}] = &extractor.Inventory{
			Name:      "stdlib",
			Version:   goVersion,
			Locations: []string{input.Path},
		}
	}

	// An additional deduplication pass is required.
	// This is necessary because the values in the map may have changed after the replacement
	dedupedPs := map[ivKey]*extractor.Inventory{}
	for _, p := range packages {
		s := ivKey{name: p.Name, version: p.Version}
		dedupedPs[s] = p
	}
	return dedupedPs, goVersion, nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	return &purl.PackageURL{
		Type:    purl.TypeGolang,
		Name:    i.Name,
		Version: i.Version,
	}
}

// Ecosystem returns the OSV Ecosystem of the software extracted by this extractor.
func (e Extractor) Ecosystem(i *extractor.Inventory) string {
	return "Go"
}

var _ filesystem.Extractor = Extractor{}
