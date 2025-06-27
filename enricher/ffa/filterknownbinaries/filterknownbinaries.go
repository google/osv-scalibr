// Package filterknownbinaries removes all packages extracted by unknown binaries
// filters out the known binaries, and records the remaining as a finding.
package filterknownbinaries

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinary"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the plugin
const Name = "filterknownbinaries"

// List of filters to apply to exclude known binaries
var filters = []filter{
	dpkgFilter{},
}

type filter interface {
	HashSetFilter(ctx context.Context, fs scalibrfs.FS, unknownBinariesSet map[string]struct{}) error
	ShouldExclude(ctx context.Context, fs scalibrfs.FS, binaryPath string) bool
	Name() string
}

// Enricher is the Java Reach enricher.
type Enricher struct {
}

// Name returns the name of the enricher.
func (Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (Enricher) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{unknownbinary.Name}
}

// Enrich enriches the inventory with Java Reach data.
func (enr Enricher) Enrich(ctx context.Context, input *enricher.ScanInput, inv *inventory.Inventory) error {
	unknownBinariesSet := map[string]struct{}{}
	filteredPackages := make([]*extractor.Package, 0, len(inv.Packages))
	for _, e := range inv.Packages {
		//Plugin contains unknownbinary.Name
		if !slices.Contains(e.Plugins, unknownbinary.Name) {
			filteredPackages = append(filteredPackages, e)
			continue
		}

		unknownBinariesSet[e.Locations[0]] = struct{}{}
	}

	// Remove all unknown binary packages from output packages
	inv.Packages = filteredPackages

	// Two sets of filters, one with a hashset that gets elements deleted out of, and another with a simple loop

	// Hash set filter
	for _, f := range filters {
		err := f.HashSetFilter(ctx, input.ScanRoot.FS, unknownBinariesSet)
		if err != nil {
			return fmt.Errorf("%s halted at %q (%q) because %w", enr.Name(), input.ScanRoot.Path, f.Name(), err)
		}
	}

	remainingPaths := maps.Keys(unknownBinariesSet)
	filteredRemainingPaths := make([]string, 0, len(unknownBinariesSet))

	// Loop Filter
RemainingPathsLoop:
	for p := range remainingPaths {
		for _, f := range filters {
			if f.ShouldExclude(ctx, input.ScanRoot.FS, p) {
				continue RemainingPathsLoop
			}
		}

		filteredRemainingPaths = append(filteredRemainingPaths, p)
	}

	// Finally join the remaining unknown paths as a big finding.
	findings := strings.Join(filteredRemainingPaths, "\n")
	inv.GenericFindings = append(inv.GenericFindings, &inventory.GenericFinding{
		Target: &inventory.GenericFindingTargetDetails{
			Extra: findings,
		},
	})

	return nil
}
