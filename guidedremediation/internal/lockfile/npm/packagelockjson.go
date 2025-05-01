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

// Package npm provides the lockfile parsing and writing for the npm package-lock.json format.
package npm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/clients/datasource"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/internal/dependencyfile/packagelockjson"
	"github.com/google/osv-scalibr/log"
)

type readWriter struct{}

// GetReadWriter returns a ReadWriter for package-lock.json lockfiles.
func GetReadWriter() (lockfile.ReadWriter, error) {
	return readWriter{}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.NPM
}

// SupportedStrategies returns the remediation strategies supported for this lockfile.
func (r readWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyInPlace}
}

type dependencyVersionSpec struct {
	Version string
	DepType dep.Type
}

type nodeModule struct {
	NodeID     resolve.NodeID
	Parent     *nodeModule
	Children   map[string]*nodeModule // keyed on package name
	Deps       map[string]dependencyVersionSpec
	ActualName string // set if the node is an alias, the real package name this refers to
}

func (n nodeModule) IsAliased() bool {
	return n.ActualName != ""
}

// Read parses the dependency graph from the given lockfile.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (*resolve.Graph, error) {
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	var lockJSON packagelockjson.LockFile
	if err := dec.Decode(&lockJSON); err != nil {
		return nil, err
	}

	// Build the node_modules directory tree in memory & add unconnected nodes into graph
	var g *resolve.Graph
	var nodeModuleTree *nodeModule
	switch {
	case lockJSON.Packages != nil:
		g, nodeModuleTree, err = nodesFromPackages(lockJSON)
	case lockJSON.Dependencies != nil:
		pkgJSONPath := filepath.ToSlash(filepath.Join(filepath.Dir(path), "package.json"))
		pkgJSONFile, ferr := fsys.Open(pkgJSONPath)
		if ferr != nil {
			return nil, fmt.Errorf("failed to open package.json (required for parsing lockfileVersion 1): %w", err)
		}
		defer pkgJSONFile.Close()
		g, nodeModuleTree, err = nodesFromDependencies(lockJSON, pkgJSONFile)
	default:
		return nil, errors.New("no dependencies in package-lock.json")
	}
	if err != nil {
		return nil, fmt.Errorf("error when parsing package-lock.json: %w", err)
	}

	// Traverse the graph (somewhat inefficiently) to add edges between nodes
	aliasNodes := make(map[resolve.NodeID]string)
	todo := []*nodeModule{nodeModuleTree}
	seen := make(map[*nodeModule]struct{})
	seen[nodeModuleTree] = struct{}{}

	for len(todo) > 0 {
		node := todo[0]
		todo = todo[1:]
		if node.IsAliased() {
			// Note which nodes that have to be renamed because of aliasing
			// Don't rename them now because we rely on the names for working out edges
			aliasNodes[node.NodeID] = node.ActualName
		}

		// Add the directory's children to the queue
		for _, child := range node.Children {
			if _, ok := seen[child]; !ok {
				todo = append(todo, child)
				seen[child] = struct{}{}
			}
		}

		// Add edges to the correct dependency nodes
		for depName, depSpec := range node.Deps {
			depNode := findDependencyNode(node, depName)
			if depNode == -1 {
				// The dependency is apparently not in the package-lock.json.
				// Either this is an uninstalled optional dependency (which is fine),
				// or lockfile is (probably) malformed, and npm would usually error installing this.
				// But there are some cases (with workspaces) that npm doesn't error,
				// so just always ignore the error to make it work.
				if !depSpec.DepType.HasAttr(dep.Opt) {
					log.Warnf("package-lock.json is missing dependency %s for %s", depName, g.Nodes[node.NodeID].Version.Name)
				}
				continue
			}
			if err := g.AddEdge(node.NodeID, depNode, depSpec.Version, depSpec.DepType); err != nil {
				return nil, err
			}
		}
	}

	// Add alias KnownAs attribute and rename them correctly
	for i, e := range g.Edges {
		if _, ok := aliasNodes[e.To]; ok {
			name := g.Nodes[e.To].Version.Name
			g.Edges[i].Type.AddAttr(dep.KnownAs, name)
		}
	}
	for i := range g.Nodes {
		if name, ok := aliasNodes[resolve.NodeID(i)]; ok {
			g.Nodes[i].Version.Name = name
		}
	}

	return g, nil
}

// Write writes the lockfile after applying the patches to outputPath.
func (r readWriter) Write(path string, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	// Read the whole package-lock.json into memory so we can use sjson to write in-place.
	f, err := fsys.Open(path)
	if err != nil {
		return err
	}
	lockf, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return err
	}

	// Map of package name to original version to new version, for easier lookup of patches.
	patchMap := make(map[string]map[string]string)
	for _, p := range patches {
		for _, pu := range p.PackageUpdates {
			if _, ok := patchMap[pu.Name]; !ok {
				patchMap[pu.Name] = make(map[string]string)
			}
			patchMap[pu.Name][pu.VersionFrom] = pu.VersionTo
		}
	}

	// We need access to the npm registry to get information about the new versions. (e.g. hashes)
	api, err := datasource.NewNPMRegistryAPIClient(filepath.Dir(outputPath))
	if err != nil {
		return fmt.Errorf("failed to connect to npm registry: %w", err)
	}

	if lockf, err = writeDependencies(lockf, patchMap, api); err != nil {
		return err
	}
	if lockf, err = writePackages(lockf, patchMap, api); err != nil {
		return err
	}

	// Write the patched lockfile to the output path.
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, lockf, 0644)
}

func findDependencyNode(node *nodeModule, depName string) resolve.NodeID {
	// Walk up the node_modules to find which node would be used as the requirement
	for node != nil {
		if child, ok := node.Children[depName]; ok {
			return child.NodeID
		}
		node = node.Parent
	}

	return resolve.NodeID(-1)
}

func reVersionAliasedDeps(deps map[string]dependencyVersionSpec) {
	// for the dependency maps, change versions from "npm:pkg@version" to "version"
	for k, v := range deps {
		_, v.Version = npm.SplitNPMAlias(v.Version)
		deps[k] = v
	}
}
