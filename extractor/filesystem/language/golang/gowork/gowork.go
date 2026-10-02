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

// Package gowork extracts Go workspace files (go.work, go.work.sum).
package gowork

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/mod/modfile"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/gowork"
)

// Extractor extracts Go packages from go.work and go.work.sum files.
//
// go.work declares the Go version (emitted as stdlib) and the local module
// directories participating in the workspace. go.work.sum pins the exact
// checksums of all resolved dependencies across those modules and is parsed
// to produce the versioned package inventory.
//
// Replace directives in go.work are applied as mutations to the packages
// found in go.work.sum: the old module name/version is replaced with the
// new one, mirroring the behaviour of the gomod extractor.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for go.work files.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "go.work"
}

type pkgKey struct {
	name    string
	version string
}

// Extract extracts packages from a go.work file and its associated go.work.sum.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	b, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read go.work: %w", err)
	}

	workFile, err := modfile.ParseWork(input.Path, b, nil)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not parse go.work: %w", err)
	}

	packages := map[pkgKey]*extractor.Package{}

	// Emit stdlib from the go directive.
	goVersion := ""
	stdlibLine := 0
	if workFile.Go != nil && workFile.Go.Version != "" {
		goVersion = workFile.Go.Version
		stdlibLine = workFile.Go.Syntax.Start.Line
	}
	// toolchain can be set to the special values "default" or "local", which
	// are not versioned Go toolchains. Only override goVersion when the name
	// starts with "go" (e.g. "go1.23.6" or "go1.23.6-bigcorp").
	if workFile.Toolchain != nil && strings.HasPrefix(workFile.Toolchain.Name, "go") {
		v, _, _ := strings.Cut(workFile.Toolchain.Name, "-")
		goVersion = strings.TrimPrefix(v, "go")
		stdlibLine = workFile.Toolchain.Syntax.Start.Line
	}
	if goVersion != "" {
		packages[pkgKey{name: "stdlib"}] = &extractor.Package{
			Name:     "stdlib",
			Version:  goVersion,
			PURLType: purl.TypeGolang,
			Location: extractor.LocationFromPathAndLine(input.Path, stdlibLine),
		}
	}

	// Parse go.work.sum for versioned dependencies.
	// filepath.ToSlash is required because input.Path uses OS path separators
	// on Windows, but fs.FS always expects forward-slash paths.
	sumPath := filepath.ToSlash(input.Path + ".sum")
	f, err := input.FS.Open(sumPath)
	if err != nil {
		log.Debugf("go.work.sum not found at %s: %v", sumPath, err)
		return inventory.Inventory{Packages: slices.Collect(maps.Values(packages))}, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			return inventory.Inventory{}, fmt.Errorf("go.work.sum: malformed line %d", lineNumber)
		}
		name := parts[0]
		version := strings.TrimPrefix(parts[1], "v")
		// Skip /go.mod lines — they verify the go.mod hash, not the module zip.
		if strings.Contains(version, "/go.mod") {
			continue
		}
		k := pkgKey{name: name, version: version}
		if _, exists := packages[k]; !exists {
			packages[k] = &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeGolang,
				Location: extractor.LocationFromPathAndLine(sumPath, lineNumber),
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("go.work.sum: scan error: %w", err)
	}

	// Apply go.work replace directives to the collected packages by updating
	// their name and version, mirroring the behaviour of the gomod extractor.
	// Local path replacements (no version on the new side) are skipped.
	for _, r := range workFile.Replace {
		if r.New.Version == "" {
			// Local path replacement — not a versioned module, skip.
			continue
		}

		var targets []pkgKey

		if r.Old.Version == "" {
			// No version on the old side: replace all versions of the module.
			for k, pkg := range packages {
				if pkg.Name == r.Old.Path {
					targets = append(targets, k)
				}
			}
		} else {
			// Specific version: only replace that exact version.
			k := pkgKey{
				name:    r.Old.Path,
				version: strings.TrimPrefix(r.Old.Version, "v"),
			}
			if _, ok := packages[k]; ok {
				targets = []pkgKey{k}
			}
		}

		for _, t := range targets {
			packages[t] = &extractor.Package{
				Name:     r.New.Path,
				Version:  strings.TrimPrefix(r.New.Version, "v"),
				PURLType: purl.TypeGolang,
				Location: extractor.LocationFromPathAndLine(input.Path, r.Syntax.Start.Line),
			}
		}
	}

	// Deduplication pass: keys may collide after replacements.
	deduped := make(map[pkgKey]*extractor.Package, len(packages))
	for _, p := range packages {
		deduped[pkgKey{name: p.Name, version: p.Version}] = p
	}

	return inventory.Inventory{Packages: slices.Collect(maps.Values(deduped))}, nil
}

var _ filesystem.Extractor = Extractor{}
