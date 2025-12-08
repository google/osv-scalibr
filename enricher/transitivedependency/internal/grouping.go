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

// Package internal contains miscellaneous functions and objects useful within transitive dependency enrichers
package internal

import (
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
)

// PackageWithIndex holds the package with its index in inv.Packages
type PackageWithIndex struct {
	Pkg   *extractor.Package
	Index int
}

// GroupPackagesFromPlugin groups packages that were added by a particular plugin by the first location
// that they are found and returns a map of location -> package name -> package with index.
func GroupPackagesFromPlugin(pkgs []*extractor.Package, pluginName string) map[string]map[string]PackageWithIndex {
	result := make(map[string]map[string]PackageWithIndex)
	for i, pkg := range pkgs {
		if !slices.Contains(pkg.Plugins, pluginName) {
			continue
		}
		if len(pkg.Locations) == 0 {
			log.Warnf("package %s has no locations", pkg.Name)
			continue
		}
		// Use the path where this package is first found.
		path := pkg.Locations[0]
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
			// This dependency is in manifest, update the version and plugins.
			i := indexPkg.Index
			inv.Packages[i].Version = pkg.Version
			inv.Packages[i].Plugins = append(inv.Packages[i].Plugins, pluginName)
		} else {
			// This dependency is not found in manifest, so it's a transitive dependency.
			inv.Packages = append(inv.Packages, pkg)
		}
	}
}
