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
	"bufio"
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
type Extractor struct {
	deduplicateSumDependencies bool
}

// Config contains the configuration options for the extractor.
type Config struct {
	// DeduplicateSumDependencies controls whether dependencies in the go.sum file
	// should be deduplicated against those in the go.mod file.
	//
	// When two dependencies with the same name and version exist, one in go.mod
	// and the other in go.sum:
	//  - If set to true, only the dependency from go.mod will be retained.
	//  - If set to false, both dependencies (from go.mod and go.sum) will be kept.
	DeduplicateSumDependencies bool
}

// DefaultConfig returns the default configuration for the extractor.
func DefaultConfig() Config {
	return Config{
		DeduplicateSumDependencies: true,
	}
}

// NewDefault returns a new instance of the extractor using the default configuration.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// New returns a new instance of the extractor.
func New(cfg Config) filesystem.Extractor {
	return &Extractor{
		deduplicateSumDependencies: cfg.DeduplicateSumDependencies,
	}
}

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

// Extract extracts packages from a go.mod file passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, fmt.Errorf("could not read %s: %w", input.Path, err)
	}
	parsedLockfile, err := modfile.Parse(input.Path, b, nil)
	if err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}

	// Store the packages in a map since they might be overwritten by later entries.
	type mapKey struct {
		name    string
		version string
		isGoSum bool
	}
	packages := map[mapKey]*extractor.Inventory{}

	for _, require := range parsedLockfile.Require {
		name := require.Mod.Path
		version := strings.TrimPrefix(require.Mod.Version, "v")
		packages[mapKey{name: name, version: version}] = &extractor.Inventory{
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
			packages[replacement] = &extractor.Inventory{
				Name:      replace.New.Path,
				Version:   strings.TrimPrefix(replace.New.Version, "v"),
				Locations: []string{input.Path},
			}
		}
	}

	isGoVersionSpecified := parsedLockfile.Go != nil && parsedLockfile.Go.Version != ""

	// At go 1.17 and above, the go command adds an indirect requirement for each module that provides any
	// package imported (even indirectly) by a package or test in the main module or passed as an argument to go get.
	//
	// for versions below extract indirect dependencies from the go.sum file
	if isGoVersionSpecified && version.Compare("go"+parsedLockfile.Go.Version, "go1.17") < 0 {
		sumPackages, err := extractFromSum(input)
		if err != nil {
			log.Warnf("Error reading go.sum file: %s", err)
		} else {
			for _, p := range sumPackages {
				packages[mapKey{name: p.Name, version: p.Version, isGoSum: true}] = p
			}
		}
	}

	// Add the Go stdlib as an explicit dependency.
	if isGoVersionSpecified {
		packages[mapKey{name: "stdlib"}] = &extractor.Inventory{
			Name:      "stdlib",
			Version:   parsedLockfile.Go.Version,
			Locations: []string{input.Path},
		}
	}

	// An additional deduplication pass is required.
	// This is necessary because the values in the map may have changed after the replacement,
	// and to ensure that sum dependencies are deduplicated when specified.
	dedupedPs := map[mapKey]*extractor.Inventory{}
	for key, p := range packages {
		keepGoSumSeparated := !e.deduplicateSumDependencies
		s := mapKey{
			name:    p.Name,
			version: p.Version,
			isGoSum: key.isGoSum && keepGoSumSeparated,
		}

		// Do not override `go.mod` dependencies with by `go.sum` ones
		if _, ok := dedupedPs[s]; ok && key.isGoSum {
			continue
		}

		dedupedPs[s] = p
	}
	return maps.Values(dedupedPs), nil
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

// extractFromSum extracts dependencies from the go.sum file.
//
// Below 1.17 go.mod does not contain indirect dependencies
// but they might be in go.sum, thus we look into it as well.
//
// Note: This function may produce false positives, as the go.sum file might be outdated.
func extractFromSum(input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	goSumPath := strings.TrimSuffix(input.Path, ".mod") + ".sum"
	f, err := input.FS.Open(goSumPath)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(f)
	packages := []*extractor.Inventory{}

	for lineNumber := 0; scanner.Scan(); lineNumber++ {
		line := scanner.Text()

		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 {
			return nil, fmt.Errorf("Error reading go.sum file: wrongly formatted line %s:%d", goSumPath, lineNumber)
		}

		name := parts[0]
		version := strings.TrimPrefix(parts[1], "v")

		// skip a line if the version contains "/go.mod" because lines
		// containing "/go.mod" are duplicates used to verify the hash of the go.mod file
		if strings.Contains(version, "/go.mod") {
			continue
		}

		packages = append(packages, &extractor.Inventory{
			Name:      name,
			Version:   version,
			Locations: []string{goSumPath},
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return packages, nil
}

var _ filesystem.Extractor = Extractor{}
