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

// Package depgraph builds a resolved dependency graph by walking the
// node_modules tree on disk. It is used by the enricher to compute
// per-vulnerability path-package scopes for the VulnPathOnly heuristic.
//
// Supported layouts:
//   - npm v3+ / yarn classic: flat <node_modules>/<pkg> with nested
//     <node_modules>/<pkg>/node_modules/<dep> when version conflicts force it.
//
// Not handled (returns a less precise graph; callers should fall through to
// IgnoreDeps):
//   - pnpm with its .pnpm flat store + symlink farm.
//   - yarn Plug'n'Play (no node_modules tree).
package depgraph

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PackageNode is one resolved package in the on-disk tree.
type PackageNode struct {
	Name    string
	Version string
	// Dir is the absolute path to the package directory.
	Dir string
	// Dependencies are the resolved deps of this package, in deterministic
	// order. Each entry is a key into Graph.Nodes (name@version).
	Dependencies []string
}

// Graph is the resolved layout indexed by name@version. Multiple installed
// versions of the same package are distinct nodes.
type Graph struct {
	// Nodes maps "name@version" → PackageNode.
	Nodes map[string]*PackageNode
	// Roots are direct deps of the project root: keys into Nodes.
	Roots []string
}

// Key returns the canonical Graph.Nodes key for a (name, version) pair.
func Key(name, version string) string { return name + "@" + version }

// Build walks <projectRoot>/node_modules, reads each package.json, and
// returns the resolved graph. Returns (nil, nil) if no node_modules tree
// exists at projectRoot — the caller should treat that as "no graph
// available" and skip VulnPathOnly.
func Build(projectRoot string) (*Graph, error) {
	// Normalize projectRoot: a trailing slash or other non-canonical form
	// breaks the literal-equality compares used downstream (fallback Roots
	// discovery, etc.) when WalkDir returns the cleaned form.
	projectRoot = filepath.Clean(projectRoot)
	rootNM := filepath.Join(projectRoot, "node_modules")
	if _, err := os.Stat(rootNM); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	g := &Graph{Nodes: map[string]*PackageNode{}}

	// Phase A: discover every (name, version, dir) triple under any
	// node_modules in the tree. Each entry is a candidate node; resolution
	// from one node's package.json `dependencies` to a concrete (name@version)
	// neighbor happens in Phase B with full visibility.
	type discovered struct {
		name, version, dir string
		jsonDeps           map[string]string
	}
	var all []discovered
	var rootJSON struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if b, err := os.ReadFile(filepath.Join(projectRoot, "package.json")); err == nil {
		_ = json.Unmarshal(b, &rootJSON)
	}

	err := filepath.WalkDir(rootNM, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Skip unreadable entries rather than abort the whole graph;
			// best-effort is better than nothing for a heuristic input.
			return nil //nolint:nilerr // intentional: skip + continue walk
		}
		if d.IsDir() || d.Name() != "package.json" {
			return nil
		}
		// Skip nested package.json files that aren't at the canonical
		// <…/node_modules/<pkg>/package.json> position (e.g. test fixtures
		// shipped inside a package's own src/ tree).
		dir := filepath.Dir(path)
		parent := filepath.Dir(dir)
		grandparent := filepath.Base(parent)
		if grandparent != "node_modules" {
			// Scoped packages: <…/node_modules/@scope/pkg/package.json>
			ggparent := filepath.Base(filepath.Dir(parent))
			if !strings.HasPrefix(filepath.Base(parent), "@") || ggparent != "node_modules" {
				return nil
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil //nolint:nilerr // intentional: skip unreadable file
		}
		var pj struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
		}
		if err := json.Unmarshal(b, &pj); err != nil {
			return nil //nolint:nilerr // intentional: skip malformed package.json
		}
		if pj.Name == "" || pj.Version == "" {
			return nil
		}
		all = append(all, discovered{
			name: pj.Name, version: pj.Version, dir: dir, jsonDeps: pj.Dependencies,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Phase B: build the Nodes map and resolve each package's
	// `dependencies` entries to a concrete neighbor by walking up parent
	// node_modules dirs — that's npm's actual resolution algorithm.
	for _, d := range all {
		k := Key(d.name, d.version)
		if _, exists := g.Nodes[k]; exists {
			continue
		}
		g.Nodes[k] = &PackageNode{Name: d.name, Version: d.version, Dir: d.dir}
	}
	for _, d := range all {
		k := Key(d.name, d.version)
		node := g.Nodes[k]
		seen := map[string]bool{}
		for depName := range d.jsonDeps {
			resolved := resolveDepFrom(d.dir, depName, rootNM)
			if resolved == "" {
				continue
			}
			if seen[resolved] {
				continue
			}
			seen[resolved] = true
			node.Dependencies = append(node.Dependencies, resolved)
		}
	}

	// Roots: direct deps declared in <root>/package.json (dependencies +
	// devDependencies — both are reachable from the project's entry points
	// at scan time, and reachability scope must include either).
	rootSeen := map[string]bool{}
	addRoot := func(name string) {
		resolved := resolveDepFrom(projectRoot, name, rootNM)
		if resolved == "" || rootSeen[resolved] {
			return
		}
		rootSeen[resolved] = true
		g.Roots = append(g.Roots, resolved)
	}
	for n := range rootJSON.Dependencies {
		addRoot(n)
	}
	for n := range rootJSON.DevDependencies {
		addRoot(n)
	}
	// Fallback if no package.json: treat every top-level node_modules entry
	// as a root, so VulnPathOnly still has something to walk from.
	if len(g.Roots) == 0 {
		for _, d := range all {
			// Plain top-level: <projectRoot>/node_modules/<pkg>
			if filepath.Dir(filepath.Dir(d.dir)) == projectRoot && filepath.Base(filepath.Dir(d.dir)) == "node_modules" {
				k := Key(d.name, d.version)
				if !rootSeen[k] {
					rootSeen[k] = true
					g.Roots = append(g.Roots, k)
				}
			}
			// Scoped top-level: <projectRoot>/node_modules/@scope/<pkg>
			// d.dir       = <projectRoot>/node_modules/@scope/<pkg>
			// Dir(d.dir)  = <projectRoot>/node_modules/@scope
			// Dir^2(d.dir)= <projectRoot>/node_modules
			// Dir^3(d.dir)= <projectRoot>
			if strings.HasPrefix(filepath.Base(filepath.Dir(d.dir)), "@") &&
				filepath.Base(filepath.Dir(filepath.Dir(d.dir))) == "node_modules" &&
				filepath.Dir(filepath.Dir(filepath.Dir(d.dir))) == projectRoot {
				k := Key(d.name, d.version)
				if !rootSeen[k] {
					rootSeen[k] = true
					g.Roots = append(g.Roots, k)
				}
			}
		}
	}
	sort.Strings(g.Roots) // deterministic across runs

	return g, nil
}

// resolveDepFrom mimics Node's lookup: start at fromDir, check its own
// node_modules/<depName>/package.json, then walk up toward rootNM. Returns
// the Graph key of the resolved package or "" if not found.
func resolveDepFrom(fromDir, depName, rootNM string) string {
	dir := fromDir
	root := filepath.Dir(rootNM)
	for {
		candidate := filepath.Join(dir, "node_modules", depName, "package.json")
		if b, err := os.ReadFile(candidate); err == nil {
			var pj struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if err := json.Unmarshal(b, &pj); err == nil && pj.Version != "" {
				name := pj.Name
				if name == "" {
					name = depName
				}
				return Key(name, pj.Version)
			}
		}
		if dir == root || dir == "/" || dir == "." {
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// IsReachable reports whether any node with the given package name is
// reachable from at least one project root via the Dependencies edges.
// Name-only — for the version-precise check use IsReachableKey, which
// callers should prefer when they have a (name, version) pair (a
// multi-version graph may have foo@1 reachable and foo@2 orphan).
func (g *Graph) IsReachable(name string) bool {
	if g == nil {
		return false
	}
	reachable := bfsReachable(g, g.Roots)
	for k, n := range g.Nodes {
		if n.Name == name && reachable[k] {
			return true
		}
	}
	return false
}

// IsReachableKey reports whether the specific (name, version) node is
// reachable from at least one project root. Use this when the vuln
// targets a specific installed version — IsReachable's name-only check
// would say "reachable" if any other version of the same name has a
// root path, even when the requested version is orphaned.
func (g *Graph) IsReachableKey(name, version string) bool {
	if g == nil {
		return false
	}
	k := Key(name, version)
	if _, ok := g.Nodes[k]; !ok {
		return false
	}
	reachable := bfsReachable(g, g.Roots)
	return reachable[k]
}

// PathsToLeaf is the name-only variant of PathsToLeafKey, retained for
// callers that genuinely want the union across all installed versions of
// the same name. New callers should prefer PathsToLeafKey when a
// (name, version) pair is available.
func (g *Graph) PathsToLeaf(leafName string) []string {
	return g.pathsTo(func(n *PackageNode) bool { return n.Name == leafName })
}

// PathsToLeafKey returns the package-name set on any root→(name@version)
// path, EXCLUDING the leaf itself. Use this version-precise form to
// avoid unioning ancestors from a sibling version of the same name (a
// multi-version graph would otherwise widen VulnPathOnly's include-set
// to packages routing to the wrong installed copy).
func (g *Graph) PathsToLeafKey(leafName, leafVersion string) []string {
	want := Key(leafName, leafVersion)
	return g.pathsTo(func(n *PackageNode) bool {
		return Key(n.Name, n.Version) == want
	})
}

func (g *Graph) pathsTo(match func(*PackageNode) bool) []string {
	if g == nil || len(g.Nodes) == 0 {
		return nil
	}
	// Find every node matching the predicate.
	var leaves []string
	for k, n := range g.Nodes {
		if match(n) {
			leaves = append(leaves, k)
		}
	}
	if len(leaves) == 0 {
		return nil
	}
	leafSet := map[string]bool{}
	for _, k := range leaves {
		leafSet[k] = true
	}

	// A node is "on a path" iff it's reachable from a root AND can reach a
	// leaf. Compute both directions and intersect.
	reachableFromRoot := bfsReachable(g, g.Roots)
	parentMap := buildReverseAdj(g)
	canReachLeaf := map[string]bool{}
	queue := append([]string(nil), leaves...)
	for _, k := range leaves {
		canReachLeaf[k] = true
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, parent := range parentMap[cur] {
			if canReachLeaf[parent] {
				continue
			}
			canReachLeaf[parent] = true
			queue = append(queue, parent)
		}
	}

	nameSet := map[string]bool{}
	for k := range g.Nodes {
		if !reachableFromRoot[k] || !canReachLeaf[k] {
			continue
		}
		if leafSet[k] {
			continue
		}
		nameSet[g.Nodes[k].Name] = true
	}
	out := make([]string, 0, len(nameSet))
	for n := range nameSet {
		out = append(out, n)
	}
	sort.Strings(out) // deterministic argv for jelly --include-packages
	return out
}

// bfsReachable returns the set of keys reachable from any seed by following
// Dependencies edges.
func bfsReachable(g *Graph, seeds []string) map[string]bool {
	out := map[string]bool{}
	queue := append([]string(nil), seeds...)
	for _, s := range seeds {
		out[s] = true
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node, ok := g.Nodes[cur]
		if !ok {
			continue
		}
		for _, d := range node.Dependencies {
			if out[d] {
				continue
			}
			out[d] = true
			queue = append(queue, d)
		}
	}
	return out
}

// buildReverseAdj returns child → parents.
func buildReverseAdj(g *Graph) map[string][]string {
	rev := map[string][]string{}
	for k, n := range g.Nodes {
		for _, d := range n.Dependencies {
			rev[d] = append(rev[d], k)
		}
	}
	return rev
}
