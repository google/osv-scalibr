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

package npm

import (
	"encoding/json"
	"io"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/internal/dependencyfile/packagelockjson"
)

// nodesFromDependencies extracts graph from old-style (npm < 7 / lockfileVersion 1) dependencies structure
// https://docs.npmjs.com/cli/v6/configuring-npm/package-lock-json
// Installed packages stored in recursive "dependencies" object
// with "requires" field listing direct dependencies, and each possibly having their own "dependencies"
// No dependency information package-lock.json for the root node, so we must also have the package.json
func nodesFromDependencies(lockJSON packagelockjson.LockFile, packageJSON io.Reader) (*resolve.Graph, *nodeModule, error) {
	// Need to grab the root requirements from the package.json, since it's not in the lockfile
	var manifestJSON npm.PackageJSON
	if err := json.NewDecoder(packageJSON).Decode(&manifestJSON); err != nil {
		return nil, nil, err
	}

	nodeModuleTree := &nodeModule{
		Children: make(map[string]*nodeModule),
		Deps:     make(map[string]dependencyVersionSpec),
	}

	// The order we process dependency types here is to match npm's behavior.
	for name, version := range manifestJSON.PeerDependencies {
		var typ dep.Type
		typ.AddAttr(dep.Scope, "peer")
		if manifestJSON.PeerDependenciesMeta[name].Optional {
			typ.AddAttr(dep.Opt, "")
		}
		nodeModuleTree.Deps[name] = dependencyVersionSpec{Version: version, DepType: typ}
	}
	for name, version := range manifestJSON.Dependencies {
		nodeModuleTree.Deps[name] = dependencyVersionSpec{Version: version}
	}
	for name, version := range manifestJSON.OptionalDependencies {
		nodeModuleTree.Deps[name] = dependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Opt)}
	}
	for name, version := range manifestJSON.DevDependencies {
		nodeModuleTree.Deps[name] = dependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Dev)}
	}
	reVersionAliasedDeps(nodeModuleTree.Deps)

	g := &resolve.Graph{}
	nodeModuleTree.NodeID = g.AddNode(resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   manifestJSON.Name,
		},
		VersionType: resolve.Concrete,
		Version:     manifestJSON.Version,
	})

	err := computeDependenciesRecursive(g, nodeModuleTree, lockJSON.Dependencies)

	return g, nodeModuleTree, err
}

func computeDependenciesRecursive(g *resolve.Graph, parent *nodeModule, deps map[string]packagelockjson.Dependency) error {
	for name, d := range deps {
		actualName, version := npm.SplitNPMAlias(d.Version)
		nID := g.AddNode(resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.NPM,
				Name:   name,
			},
			VersionType: resolve.Concrete,
			Version:     version,
		})
		nm := &nodeModule{
			Parent:     parent,
			NodeID:     nID,
			Children:   make(map[string]*nodeModule),
			Deps:       make(map[string]dependencyVersionSpec),
			ActualName: actualName,
		}

		// The requires map includes regular dependencies AND optionalDependencies
		// but it does not include peerDependencies or devDependencies.
		// The generated graphs will lack the edges between peers
		for name, version := range d.Requires {
			nm.Deps[name] = dependencyVersionSpec{Version: version}
		}
		reVersionAliasedDeps(nm.Deps)

		parent.Children[name] = nm
		if d.Dependencies != nil {
			if err := computeDependenciesRecursive(g, nm, d.Dependencies); err != nil {
				return err
			}
		}
	}

	return nil
}
