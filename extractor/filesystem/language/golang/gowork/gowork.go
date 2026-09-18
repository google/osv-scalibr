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
	"path/filepath"
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
	if workFile.Toolchain != nil && workFile.Toolchain.Name != "" {
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

	// Extract versioned replace targets from go.work replace directives.
	// Local path replacements (no version) are skipped.
	for _, r := range workFile.Replace {
		if r.New.Version == "" {
			continue
		}
		version := strings.TrimPrefix(r.New.Version, "v")
		k := pkgKey{name: r.New.Path, version: version}
		packages[k] = &extractor.Package{
			Name:     r.New.Path,
			Version:  version,
			PURLType: purl.TypeGolang,
			Location: extractor.LocationFromPathAndLine(input.Path, r.Syntax.Start.Line),
		}
	}

	// Parse go.work.sum for versioned dependencies.
	sumPath := input.Path + ".sum"
	f, err := input.FS.Open(sumPath)
	if err != nil {
		log.Debugf("go.work.sum not found at %s: %v", sumPath, err)
		pkgs := make([]*extractor.Package, 0, len(packages))
		for _, p := range packages {
			pkgs = append(pkgs, p)
		}
		return inventory.Inventory{Packages: pkgs}, nil
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

	pkgs := make([]*extractor.Package, 0, len(packages))
	for _, p := range packages {
		pkgs = append(pkgs, p)
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

var _ filesystem.Extractor = Extractor{}
