// Package inventorysorter provides a Sort function for inventories to allow
// clear comparisons with cmp.Diff()
package inventorysorter

import (
	"cmp"
	"slices"

	"github.com/google/osv-scalibr/extractor"
)

// Sort sorts the inventories in-place to allow cmp matching
// This does not sort all available fields (e.g. Metadata)
func Sort(inv []*extractor.Inventory, ext extractor.Extractor) {
	slices.SortFunc(inv, func(a, b *extractor.Inventory) int {
		purlA, _ := ext.ToPURL(a)
		purlB, _ := ext.ToPURL(b)
		return cmp.Compare(purlA.String(), purlB.String())
	})
}
