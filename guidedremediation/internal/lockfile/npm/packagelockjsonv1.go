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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
	"github.com/google/osv-scalibr/internal/dependencyfile/packagelockjson"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
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

// writeDependencies writes the patches to the "dependencies" section (v1) of the lockfile (if it exists).
func writeDependencies(lockf []byte, patchMap map[string]map[string]string, api *datasource.NPMRegistryAPIClient) ([]byte, error) {
	if !gjson.GetBytes(lockf, "packages").Exists() {
		return lockf, nil
	}
	// Check if the lockfile is using CRLF or LF by checking the first newline.
	i := slices.Index(lockf, byte('\n'))
	crlf := i > 0 && lockf[i-1] == '\r'

	return writeDependenciesRecursive(lockf, patchMap, api, "dependencies", 1, crlf)
}

func writeDependenciesRecursive(lockf []byte, patchMap map[string]map[string]string, api *datasource.NPMRegistryAPIClient, path string, depth int, crlf bool) ([]byte, error) {
	for pkg, data := range gjson.GetBytes(lockf, path).Map() {
		pkgPath := path + "." + gjson.Escape(pkg)
		if data.Get("dependencies").Exists() {
			var err error
			lockf, err = writeDependenciesRecursive(lockf, patchMap, api, pkgPath+".dependencies", depth+1, crlf)
			if err != nil {
				return nil, err
			}
		}
		isAlias := false
		realPkg, version := npm.SplitNPMAlias(data.Get("version").String())
		if realPkg != "" {
			isAlias = true
			pkg = realPkg
		}

		if upgrades, ok := patchMap[pkg]; ok {
			if version, ok := upgrades[version]; ok {
				// update dependency in place
				npmData, err := api.FullJSON(context.Background(), pkg, version)
				if err != nil {
					return lockf, err
				}
				// The only necessary fields to update appear to be "version", "resolved", "integrity", and "requires"
				newVersion := npmData.Get("version").String()
				if isAlias {
					newVersion = "npm:" + pkg + "@" + newVersion
				}
				// These shouldn't error.
				lockf, _ = sjson.SetBytes(lockf, pkgPath+".version", newVersion)
				lockf, _ = sjson.SetBytes(lockf, pkgPath+".resolved", npmData.Get("dist.tarball").String())
				lockf, _ = sjson.SetBytes(lockf, pkgPath+".integrity", npmData.Get("dist.integrity").String())
				// formatting & padding to output for the correct level at this depth
				pretty := fmt.Sprintf("|@pretty:{\"prefix\": %q}", strings.Repeat(" ", 4*depth+2))
				reqs := npmData.Get("dependencies" + pretty)
				if !reqs.Exists() {
					lockf, _ = sjson.DeleteBytes(lockf, pkgPath+".requires")
				} else {
					text := reqs.Raw
					// remove trailing newlines that @pretty creates for objects
					text = strings.TrimSuffix(text, "\n")
					if crlf {
						text = strings.ReplaceAll(text, "\n", "\r\n")
					}
					lockf, _ = sjson.SetRawBytes(lockf, pkgPath+".requires", []byte(text))
				}
			}
		}
	}

	return lockf, nil
}
