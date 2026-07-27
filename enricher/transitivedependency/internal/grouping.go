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

// Package internal contains miscellaneous functions and objects useful within transitive dependency enrichers
package internal

import (
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
)

// PackageWithIndex holds the package with its index in inv.Packages
type PackageWithIndex struct {
	Pkg   *extractor.Package
	Index int
}

// GroupPackagesFromPlugin groups packages that were added by a particular plugin by their
// descriptor's path and returns a map of path -> package name -> package with index.
func GroupPackagesFromPlugin(pkgs []*extractor.Package, pluginName string) map[string]map[string]PackageWithIndex {
	result := make(map[string]map[string]PackageWithIndex)
	for i, pkg := range pkgs {
		if !slices.Contains(pkg.Plugins, pluginName) {
			continue
		}
		if pkg.Location.Descriptor == nil || pkg.Location.Descriptor.File == nil {
			log.Warnf("package %s has no descriptor path", pkg.Name)
			continue
		}
		// Use the path where this package is first found.
		path := pkg.Location.Descriptor.File.Path
		if _, ok := result[path]; !ok {
			result[path] = make(map[string]PackageWithIndex)
		}
		result[path][pkg.Name] = PackageWithIndex{pkg, i}
	}
	return result
}

// Add handles supplementing an inventory with enriched packages
func Add(enrichedPkgs []*extractor.Package, inv *inventory.Inventory, pluginName string, existingPackages map[string]PackageWithIndex) {
	for _, pkg := range enrichedPkgs {
		indexPkg, ok := existingPackages[pkg.Name]
		if ok {
			// This dependency is in manifest, update the version, plugins and parent IDs.
			i := indexPkg.Index
			inv.Packages[i].Version = pkg.Version
			inv.Packages[i].Plugins = append(inv.Packages[i].Plugins, pluginName)

			if len(pkg.ParentIDs) > 0 && inv.Packages[i].ParentIDs == nil {
				inv.Packages[i].ParentIDs = make(map[string]bool)
			}

			for parentID := range pkg.ParentIDs {
				inv.Packages[i].ParentIDs[parentID] = true
			}
		} else {
			// This dependency is not found in manifest, so it's a transitive dependency.
			inv.Packages = append(inv.Packages, pkg)
		}
	}
}

// GetNameToIDMapping returns a mapping of package name to package ID for a given list of packages
// and a dependency graph. Known packages without IDs will have IDs added using the ID generator.
func GetNameToIDMapping(g *resolve.Graph, packages []*extractor.Package, idGenerator extractor.IDGenerator) (map[string]string, error) {
	nameToID := make(map[string]string)
	for _, pkg := range packages {
		id, err := pkg.RequireID(idGenerator)
		if err != nil {
			return nil, err
		}
		nameToID[pkg.Name] = id
	}

	for i := 1; i < len(g.Nodes); i++ {
		node := g.Nodes[i]
		if _, ok := nameToID[node.Version.Name]; !ok {
			id, err := idGenerator.GenerateID(node.Version.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to generate random UUID: %w", err)
			}
			nameToID[node.Version.Name] = id
		}
	}
	return nameToID, nil
}

// GetParentIDs returns the set of parent IDs for a node in a dependency graph.
func GetParentIDs(g *resolve.Graph, nameToID map[string]string, nodeID resolve.NodeID) (map[string]bool, error) {
	parents := make(map[string]bool)
	for _, edge := range g.Edges {
		if edge.To == nodeID {
			if int(edge.From) >= len(g.Nodes) {
				return nil, fmt.Errorf("parent id %v is out of range for nodes (length %v)", edge.From, len(g.Nodes))
			}
			if edge.From == 0 {
				parents["root"] = true
				continue
			}
			parentPkgName := g.Nodes[edge.From].Version.Name
			parentPkgID, ok := nameToID[parentPkgName]
			if !ok {
				return nil, fmt.Errorf("parent package %q not found in known packages", parentPkgName)
			}
			parents[parentPkgID] = true
		}
	}
	return parents, nil
}
