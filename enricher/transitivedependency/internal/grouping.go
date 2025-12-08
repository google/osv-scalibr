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
