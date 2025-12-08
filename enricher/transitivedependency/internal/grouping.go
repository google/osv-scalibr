package internal

import (
	"slices"

	"github.com/google/osv-scalibr/extractor"
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
