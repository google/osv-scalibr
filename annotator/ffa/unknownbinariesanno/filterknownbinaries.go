// Package unknownbinariesanno removes all packages extracted by unknown binaries
// filters out the known binaries, and records the remaining as a finding.
package unknownbinariesanno

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/dpkgfilter"
	"github.com/google/osv-scalibr/annotator/ffa/unknownbinariesanno/internal/filter"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Name of the plugin
const Name = "ffa/unknownbinaries"

// List of filters to apply to exclude known binaries
var filters = []filter.Filter{
	dpkgfilter.DpkgFilter{},
}

// Annotator further processes the UnknownBinaryExtractor
type Annotator struct {
}

// Annotate removes all packages extracted by unknown binaries,
// filters out the known binaries, and records the remaining as a finding.
func (anno *Annotator) Annotate(ctx context.Context, input *annotator.ScanInput, inv *inventory.Inventory) error {
	unknownBinariesSet := map[string]struct{}{}
	filteredPackages := make([]*extractor.Package, 0, len(inv.Packages))
	for _, e := range inv.Packages {
		if !slices.Contains(e.Plugins, unknownbinariesextr.Name) {
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
			return fmt.Errorf("%s halted at %q (%q) because %w", anno.Name(), input.ScanRoot.Path, f.Name(), err)
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

var _ annotator.Annotator = &Annotator{}

// Name returns the name of the enricher.
func (*Annotator) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (*Annotator) Version() int {
	return 0
}

// Requirements returns the requirements of the enricher.
func (*Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (*Annotator) RequiredPlugins() []string {
	return []string{unknownbinariesextr.Name}
}
