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

package npm

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/internal/dependencyfile/packagelockjson"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// nodesFromPackages extracts graph from new-style (npm >= 7 / lockfileVersion 2+) structure
// https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json
// Installed packages are in the flat "packages" object, keyed by the install path
// e.g. "node_modules/foo/node_modules/bar"
// packages contain most information from their own manifests.
func nodesFromPackages(lockJSON packagelockjson.LockFile) (*resolve.Graph, *nodeModule, error) {
	g := &resolve.Graph{}
	// Create graph nodes and reconstruct the node_modules folder structure in memory
	root, ok := lockJSON.Packages[""]
	if !ok {
		return nil, nil, errors.New("missing root node")
	}
	nID := g.AddNode(resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.NPM,
			Name:   root.Name,
		},
		VersionType: resolve.Concrete,
		Version:     root.Version,
	})
	nodeModuleTree := makeNodeModuleDeps(root, true)
	nodeModuleTree.NodeID = nID

	// paths for npm workspace subfolders, not inside root node_modules
	workspaceModules := make(map[string]*nodeModule)
	workspaceModules[""] = nodeModuleTree

	// iterate keys by node_modules depth
	for _, k := range packageNamesByNodeModuleDepth(lockJSON.Packages) {
		if k == "" {
			// skip the root node
			continue
		}
		pkg, ok := lockJSON.Packages[k]
		if !ok {
			return nil, nil, fmt.Errorf("expected key %q not found in packages", k)
		}
		path := strings.Split(k, "node_modules/")
		if len(path) == 1 {
			// the path does not contain "node_modules/", assume this is a workspace directory
			nID := g.AddNode(resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.NPM,
					Name:   path[0], // This will get replaced by the name from the symlink
				},
				VersionType: resolve.Concrete,
				Version:     pkg.Version,
			})
			m := makeNodeModuleDeps(pkg, true) // NB: including the dev dependencies
			m.NodeID = nID
			workspaceModules[path[0]] = m

			continue
		}

		if pkg.Link {
			// This is the symlink to the workspace directory in node_modules
			if len(path) != 2 || path[0] != "" {
				// Not sure if this situation is actually possible.
				return nil, nil, errors.New("found symlink in package-lock.json that's not in root node_modules directory")
			}
			m := workspaceModules[pkg.Resolved]
			if m == nil {
				// Not sure if this situation is actually possible.
				return nil, nil, errors.New("symlink in package-lock.json processed before real directory")
			}

			// attach the workspace to the tree
			pkgName := path[1]
			nodeModuleTree.Children[pkgName] = m
			if pkg.Resolved == "" {
				// weird case: the root directory is symlinked into its own node_modules
				continue
			}
			m.Parent = nodeModuleTree

			// rename the node to the name it would be referred to as in package.json
			g.Nodes[m.NodeID].Version.Name = pkgName
			// add it as a dependency of the root node, so it's not orphaned
			if _, ok := nodeModuleTree.Deps[pkgName]; !ok {
				nodeModuleTree.Deps[pkgName] = dependencyVersionSpec{Version: "*"}
			}

			continue
		}

		// find the direct parent package by traversing the path
		parent := nodeModuleTree
		if path[0] != "" {
			// jump to the corresponding workspace if package is in one
			if parent, ok = workspaceModules[strings.TrimSuffix(path[0], "/")]; !ok {
				// The package exists in a node_modules of a folder that doesn't belong to this project.
				// npm seems to silently ignore these, so we will too.
				continue
			}
		}

		parentFound := true
		for _, p := range path[1 : len(path)-1] { // skip root directory
			p = strings.TrimSuffix(p, "/")
			if parent, parentFound = parent.Children[p]; !parentFound {
				break
			}
		}

		if !parentFound {
			// The package this supposed to be installed under is not installed.
			// npm seems to silently ignore these, so we will too.
			continue
		}

		name := path[len(path)-1]
		nID := g.AddNode(resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.NPM,
				Name:   name,
			},
			VersionType: resolve.Concrete,
			Version:     pkg.Version,
		})
		parent.Children[name] = makeNodeModuleDeps(pkg, false)
		parent.Children[name].NodeID = nID
		parent.Children[name].Parent = parent
		parent.Children[name].ActualName = pkg.Name
	}

	return g, nodeModuleTree, nil
}

func makeNodeModuleDeps(pkg packagelockjson.Package, includeDev bool) *nodeModule {
	nm := nodeModule{
		Children: make(map[string]*nodeModule),
		Deps:     make(map[string]dependencyVersionSpec),
	}

	// The order we process dependency types here is to match npm's behavior.
	for name, version := range pkg.PeerDependencies {
		var typ dep.Type
		typ.AddAttr(dep.Scope, "peer")
		if pkg.PeerDependenciesMeta[name].Optional {
			typ.AddAttr(dep.Opt, "")
		}
		nm.Deps[name] = dependencyVersionSpec{Version: version, DepType: typ}
	}
	for name, version := range pkg.Dependencies {
		nm.Deps[name] = dependencyVersionSpec{Version: version}
	}
	for name, version := range pkg.OptionalDependencies {
		nm.Deps[name] = dependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Opt)}
	}
	if includeDev {
		for name, version := range pkg.DevDependencies {
			nm.Deps[name] = dependencyVersionSpec{Version: version, DepType: dep.NewType(dep.Dev)}
		}
	}
	reVersionAliasedDeps(nm.Deps)

	return &nm
}

func packageNamesByNodeModuleDepth(packages map[string]packagelockjson.Package) []string {
	keys := slices.Collect(maps.Keys(packages))
	slices.SortFunc(keys, func(a, b string) int {
		aSplit := strings.Split(a, "node_modules/")
		bSplit := strings.Split(b, "node_modules/")
		if c := cmp.Compare(len(aSplit), len(bSplit)); c != 0 {
			return c
		}
		// sort alphabetically if they're the same depth
		return cmp.Compare(a, b)
	})

	return keys
}

// writePackages writes the patches to the "packages" section (v2+) of the lockfile (if it exists).
func writePackages(lockf []byte, patchMap map[string]map[string]string, api *datasource.NPMRegistryAPIClient) ([]byte, error) {
	// Check if the lockfile is using CRLF or LF by checking the first newline.
	i := slices.Index(lockf, byte('\n'))
	crlf := i > 0 && lockf[i-1] == '\r'
	packages := gjson.GetBytes(lockf, "packages")
	if !packages.Exists() {
		return lockf, nil
	}

	for key, value := range packages.Map() {
		parts := strings.Split(key, "node_modules/")
		if len(parts) == 0 {
			continue
		}
		pkg := parts[len(parts)-1]
		if n := value.Get("name"); n.Exists() { // if this is an alias, use the real package as the name
			pkg = n.String()
		}
		if upgrades, ok := patchMap[pkg]; ok {
			if newVer, ok := upgrades[value.Get("version").String()]; ok {
				fullPath := "packages." + gjson.Escape(key)
				var err error
				if lockf, err = updatePackage(lockf, fullPath, pkg, newVer, api, crlf); err != nil {
					return lockf, err
				}
			}
		}
	}

	return lockf, nil
}

func updatePackage(lockf []byte, fullPath string, pkg string, newVer string, api *datasource.NPMRegistryAPIClient, crlf bool) ([]byte, error) {
	npmData, err := api.FullJSON(context.Background(), pkg, newVer)
	if err != nil {
		return lockf, err
	}

	// The "dependencies" returned from the registry may include both optional and regular dependencies,
	// but the "optionalDependencies" are removed from "dependencies" in package-lock.json.
	for _, opt := range npmData.Get("optionalDependencies|@keys").Array() {
		depName := gjson.Escape(opt.String())
		s, _ := sjson.Delete(npmData.Raw, "dependencies."+depName)
		npmData = gjson.Parse(s)
	}

	if len(npmData.Get("dependencies").Map()) == 0 {
		s, _ := sjson.Delete(npmData.Raw, "dependencies")
		npmData = gjson.Parse(s)
	}

	pkgData := gjson.GetBytes(lockf, fullPath)
	pkgText := pkgData.Raw

	// There doesn't appear to be a consistent list of what fields should be included in package-lock.json packages.
	// https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json#packages seems list some,
	// but it's not exhaustive and some listed fields may be missing in package-lock files in the wild.
	// It may depend on the npm version.
	// Just modify the fields that are already present to avoid too much churn.
	keyArray := pkgData.Get("@keys").Array()
	// If dependency types were not previously present, we want to add them.
	necessaryKeys := []string{"dependencies", "optionalDependencies", "peerDependencies"}
	keys := make([]string, len(keyArray), len(keyArray)+len(necessaryKeys))
	for i, key := range keyArray {
		keys[i] = gjson.Escape(key.String())
	}
	for _, key := range necessaryKeys {
		if npmData.Get(key).Exists() && !pkgData.Get(key).Exists() {
			keys = append(keys, key)
		}
	}

	// Write all the updated fields
	for _, key := range keys {
		// some keys require special handling.
		switch key {
		case "resolved":
			pkgText, _ = sjson.Set(pkgText, "resolved", npmData.Get("dist.tarball").String())
		case "integrity":
			pkgText, _ = sjson.Set(pkgText, "integrity", npmData.Get("dist.integrity").String())
		case "bin":
			// the api formats the paths as "./path/to", while package-lock.json seem to use "path/to"
			newVal := npmData.Get("bin")
			if newVal.Exists() {
				text := newVal.Raw
				for k, v := range newVal.Map() {
					text, _ = sjson.Set(text, k, filepath.Clean(v.String()))
				}
				pkgText, _ = sjson.SetRaw(pkgText, "bin", text)
			} else {
				// explicitly remove it if it's no longer present.
				pkgText, _ = sjson.Delete(pkgText, "bin")
			}
		case "dependencies", "devDependencies", "peerDependencies", "optionalDependencies":
			// If all dependencies of a type have been removed, explicitly remove the field.
			// NB: devDependencies shouldn't be in the lockfile anyway.
			if !npmData.Get(key).Exists() {
				pkgText, _ = sjson.Delete(pkgText, key)
				continue
			}
			fallthrough
		default:
			newVal := npmData.Get(key)
			if newVal.Exists() {
				pkgText, _ = sjson.SetRaw(pkgText, key, newVal.Raw)
			}
		}
	}

	// Pretty-print the JSON because setting nested fields break the formatting.
	// setting prefix to match indentation at the level.
	pkgText = gjson.Get(pkgText, "@this|@pretty:{\"prefix\": \"    \", \"intent\": \"  \"}").Raw
	// Trim trailing newline that @pretty creates.
	pkgText = strings.TrimSuffix(pkgText, "\n")
	if crlf {
		pkgText = strings.ReplaceAll(pkgText, "\n", "\r\n")
	}

	return sjson.SetRawBytes(lockf, fullPath, []byte(pkgText))
}
