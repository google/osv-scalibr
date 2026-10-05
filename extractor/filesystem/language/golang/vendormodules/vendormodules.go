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

// Package vendormodules extracts Go vendor/modules.txt files.
package vendormodules

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"golang.org/x/mod/module"
)

const (
	// Name is the unique name of this extractor.
	Name = "go/vendormodules"
)

type pkgKey struct {
	name    string
	version string
}

type moduleEntry struct {
	name       string
	version    string
	lineNumber int
}

// Extractor extracts Go packages from vendor/modules.txt files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Go vendored module manifests.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	// Normalize both OS-native paths and Windows-style paths used by tests.
	path := strings.ReplaceAll(api.Path(), "\\", "/")
	path = filepath.ToSlash(filepath.Clean(path))
	return path == "vendor/modules.txt" || strings.HasSuffix(path, "/vendor/modules.txt")
}

// Extract extracts packages from vendor/modules.txt files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	packages := map[pkgKey]*extractor.Package{}
	var pending *moduleEntry

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		if err := ctx.Err(); err != nil {
			return inventory.Inventory{}, fmt.Errorf("%s halted due to context error: %w", e.Name(), err)
		}

		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# ") {
			pending = nil
			name, version, ok := parseModuleHeader(line)
			if ok {
				pending = &moduleEntry{name: name, version: version, lineNumber: lineNumber}
			}
			continue
		}

		if pending == nil || !isVendoredPackageLine(line) {
			continue
		}

		key := pkgKey{name: pending.name, version: pending.version}
		if _, ok := packages[key]; !ok {
			packages[key] = packageFromModuleEntry(input.Path, pending)
		}
		// Emit once per module header. Additional package lines under the same
		// header do not change the module-level inventory record.
		pending = nil
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	return inventory.Inventory{Packages: sortedPackages(packages)}, nil
}

func packageFromModuleEntry(path string, entry *moduleEntry) *extractor.Package {
	return &extractor.Package{
		Name:     entry.name,
		Version:  entry.version,
		PURLType: purl.TypeGolang,
		Location: extractor.LocationFromPathAndLine(path, entry.lineNumber),
	}
}

func sortedPackages(packages map[pkgKey]*extractor.Package) []*extractor.Package {
	if len(packages) == 0 {
		return nil
	}

	pkgs := make([]*extractor.Package, 0, len(packages))
	for _, pkg := range packages {
		pkgs = append(pkgs, pkg)
	}
	slices.SortFunc(pkgs, func(a, b *extractor.Package) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return pkgs
}

func parseModuleHeader(line string) (string, string, bool) {
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#")))
	if len(fields) < 2 {
		return "", "", false
	}

	arrow := slices.Index(fields, "=>")
	if arrow == -1 {
		return moduleFromFields(fields)
	}

	replacementName, replacementVersion, ok := moduleFromFields(fields[arrow+1:])
	if ok {
		return replacementName, replacementVersion, true
	}

	if isLocalReplacement(fields[arrow+1:]) {
		return moduleFromFields(fields[:arrow])
	}

	return "", "", false
}

func moduleFromFields(fields []string) (string, string, bool) {
	// The selected module identity is encoded as exactly "module version".
	if len(fields) != 2 {
		return "", "", false
	}
	return normalizeModule(fields[0], fields[1])
}

func normalizeModule(name, version string) (string, string, bool) {
	if err := module.Check(name, version); err != nil {
		return "", "", false
	}
	return name, strings.TrimPrefix(version, "v"), true
}

func isLocalReplacement(fields []string) bool {
	if len(fields) != 1 {
		return false
	}

	path := fields[0]
	return strings.HasPrefix(path, "./") ||
		strings.HasPrefix(path, "../") ||
		strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, ".\\") ||
		strings.HasPrefix(path, "..\\")
}

func isVendoredPackageLine(line string) bool {
	if line == "" || strings.HasPrefix(line, "#") {
		return false
	}
	return module.CheckImportPath(line) == nil
}

var _ filesystem.Extractor = Extractor{}
