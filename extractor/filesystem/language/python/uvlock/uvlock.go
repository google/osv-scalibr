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

// Package uvlock extracts uv.lock files.
package uvlock

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "python/uvlock"
)

type uvLockPackageSource struct {
	Virtual  string `toml:"virtual"`
	Editable string `toml:"editable"`
	Git      string `toml:"git"`
}

type uvLockDependency struct {
	Name    string   `toml:"name"`
	Version string   `toml:"version"`
	Extra   []string `toml:"extra"`
}

type uvLockPackage struct {
	Name                 string                        `toml:"name"`
	Version              string                        `toml:"version"`
	Source               uvLockPackageSource           `toml:"source"`
	Dependencies         []uvLockDependency            `toml:"dependencies"`
	OptionalDependencies map[string][]uvLockDependency `toml:"optional-dependencies"`
	DevDependencies      map[string][]uvLockDependency `toml:"dev-dependencies"`
}

type uvLockManifest struct {
	Members          []string                       `toml:"members"`
	DependencyGroups map[string][]uvLockRequirement `toml:"dependency-groups"`
}

type uvLockRequirement struct {
	Name   string   `toml:"name"`
	Extras []string `toml:"extras"`
}

type uvLockFile struct {
	Version  int             `toml:"version"`
	Manifest uvLockManifest  `toml:"manifest"`
	Packages []uvLockPackage `toml:"package"`
}

// depNode is a package in the dependency graph, either with its regular
// dependencies (empty extra) or with the dependencies of one of its extras.
type depNode struct {
	pkg   int
	extra string
}

type depGraph struct {
	pkgs   []uvLockPackage
	byName map[string][]int
}

// Extractor extracts python packages from uv.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor
func (e Extractor) Name() string { return Name }

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
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	content, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not read file: %w", err)
	}

	var parsedLockfile uvLockFile
	if err := toml.Unmarshal(content, &parsedLockfile); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	packageNames := make([]string, 0, len(parsedLockfile.Packages))
	for _, p := range parsedLockfile.Packages {
		packageNames = append(packageNames, p.Name)
	}
	lineNums := findPackageLineNumbers(content, packageNames)

	packages := make([]*extractor.Package, 0, len(parsedLockfile.Packages))
	depGroups := resolveGroups(parsedLockfile)

	for i, lockPackage := range parsedLockfile.Packages {
		// skip including the root "package", since its name and version are most likely arbitrary
		if lockPackage.Source.Virtual == "." {
			continue
		}

		_, commit, _ := strings.Cut(lockPackage.Source.Git, "#")

		pkgDetails := &extractor.Package{
			Name:     lockPackage.Name,
			Version:  lockPackage.Version,
			PURLType: purl.TypePyPi,
			Location: extractor.LocationFromPathAndLine(input.Path, lineNums[i]),
		}

		if commit != "" {
			pkgDetails.SourceCode = &extractor.SourceCodeIdentifier{
				Commit: commit,
			}
		}

		pkgDetails.Metadata = &osv.DepGroupMetadata{
			DepGroupVals: depGroups[i],
		}
		packages = append(packages, pkgDetails)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// resolveGroups returns the sorted groups of each package, indexed like
// lockfile.Packages. The roots' groups spread to everything they pull in.
func resolveGroups(lockfile uvLockFile) [][]string {
	g := depGraph{
		pkgs:   lockfile.Packages,
		byName: make(map[string][]int, len(lockfile.Packages)),
	}
	for i, p := range lockfile.Packages {
		g.byName[p.Name] = append(g.byName[p.Name], i)
	}

	// Production wins, like in poetrylock: a package that ships must be scanned.
	// Roots count too, since groups can point back at them (dev = ["app[cli]"]).
	prod := make(map[depNode]bool)
	groupDeps := make(map[string][]uvLockDependency)
	for _, i := range findRoots(lockfile) {
		g.visit(depNode{pkg: i}, prod, nil)
		root := lockfile.Packages[i]
		for name, deps := range root.OptionalDependencies {
			groupDeps[name] = append(groupDeps[name], deps...)
		}
		for name, deps := range root.DevDependencies {
			groupDeps[name] = append(groupDeps[name], deps...)
		}
	}

	// A workspace root without a [project] table has no [[package]], so uv
	// keeps its groups in the manifest.
	for name, reqs := range lockfile.Manifest.DependencyGroups {
		for _, r := range reqs {
			groupDeps[name] = append(groupDeps[name], uvLockDependency{Name: r.Name, Extra: r.Extras})
		}
	}

	groups := make([][]string, len(lockfile.Packages))
	for i := range groups {
		groups[i] = []string{}
	}

	for name, deps := range groupDeps {
		seen := make(map[depNode]bool)
		g.walk(deps, seen, prod)
		for n := range seen {
			if n.extra == "" {
				groups[n.pkg] = append(groups[n.pkg], name)
			}
		}
	}

	for _, pkgGroups := range groups {
		slices.Sort(pkgGroups)
	}

	return groups
}

// findRoots returns the indexes of the root projects. uv sorts packages by
// name, so the root isn't necessarily the last [[package]].
func findRoots(lockfile uvLockFile) []int {
	var roots []int
	for i, p := range lockfile.Packages {
		isRoot := p.Source.Virtual == "." || p.Source.Editable == "."
		if len(lockfile.Manifest.Members) > 0 {
			isRoot = slices.Contains(lockfile.Manifest.Members, p.Name)
		}
		if isRoot {
			roots = append(roots, i)
		}
	}
	return roots
}

// walk adds every node that installing deps pulls in to seen. Nodes in skip,
// and everything only reachable through them, are left out.
func (g depGraph) walk(deps []uvLockDependency, seen, skip map[depNode]bool) {
	for _, dep := range deps {
		for _, i := range g.byName[dep.Name] {
			// uv only writes the version when several packages share the name.
			if dep.Version != "" && dep.Version != g.pkgs[i].Version {
				continue
			}

			g.visit(depNode{pkg: i}, seen, skip)
			for _, extra := range dep.Extra {
				g.visit(depNode{pkg: i, extra: extra}, seen, skip)
			}
		}
	}
}

func (g depGraph) visit(n depNode, seen, skip map[depNode]bool) {
	if seen[n] || skip[n] {
		return
	}
	seen[n] = true

	if n.extra == "" {
		g.walk(g.pkgs[n.pkg].Dependencies, seen, skip)
	} else {
		g.walk(g.pkgs[n.pkg].OptionalDependencies[n.extra], seen, skip)
	}
}

// extractPackageName parses a TOML key-value line and returns the unquoted
// package name if the key is "name". Returns false if the line is not a valid name assignment.
// TODO(b/491518484): Put in common location for all Python extractors to use.
func extractPackageName(line string) (string, bool) {
	if !strings.HasPrefix(line, "name") {
		return "", false
	}

	k, _, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(k) != "name" {
		return "", false
	}

	var pkg uvLockPackage
	if err := toml.Unmarshal([]byte(line), &pkg); err != nil {
		return "", false
	}

	return pkg.Name, true
}

// findPackageLineNumbers returns an array of line numbers that correspond to the array of package
// names passed in.
func findPackageLineNumbers(content []byte, packageNames []string) []int {
	lineNums := make([]int, len(packageNames))
	if len(packageNames) == 0 {
		return lineNums
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	pkgIdx := 0
	inPackageBlock := false
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			inPackageBlock = true
			continue
		}

		if inPackageBlock && strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[[package]]") {
			inPackageBlock = false
			continue
		}

		if !inPackageBlock || pkgIdx >= len(packageNames) {
			continue
		}

		extractedName, ok := extractPackageName(line)
		if !ok || extractedName != packageNames[pkgIdx] {
			continue
		}

		lineNums[pkgIdx] = lineNum
		pkgIdx++
		inPackageBlock = false

		if pkgIdx == len(packageNames) {
			break
		}
	}

	return lineNums
}

var _ filesystem.Extractor = Extractor{}
