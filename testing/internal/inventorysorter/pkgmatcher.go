// Package inventorysorter provides a Sort function for inventories to allow
// clear comparisons with cmp.Diff()
package inventorysorter

import (
	"cmp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
)

// Sort sorts the inventories in-place to allow cmp matching
// This does not sort all available fields (e.g. Metadata)
func Sort(inv []*extractor.Inventory) {
	slices.SortFunc(inv, func(a, b *extractor.Inventory) int {
		// TODO: Is there a better way to compare SourceCode?
		sourceComparison := 0
		if a.SourceCode != nil && b.SourceCode != nil {
			sourceComparison = cmp.Or(
				cmp.Compare(a.SourceCode.Repo, b.SourceCode.Repo),
				cmp.Compare(a.SourceCode.Commit, b.SourceCode.Commit),
			)
		} else if a.SourceCode == nil {
			sourceComparison = -1
		} else if b.SourceCode == nil {
			sourceComparison = 1
		}

		return cmp.Or(
			cmp.Compare(strings.Join(a.Locations, "//"), strings.Join(b.Locations, "//")),
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.Version, b.Version),
			sourceComparison,
		)
	})
}
