package extracttest

import (
	"cmp"
	"fmt"

	"github.com/google/osv-scalibr/extractor"
)

// InventoryCmpLess returns whether Inventory a is less than b.
func InventoryCmpLess(a, b *extractor.Inventory) bool {
	aLoc := fmt.Sprintf("%v", a.Locations)
	bLoc := fmt.Sprintf("%v", b.Locations)

	var aExtr, bExtr string
	if a.Extractor != nil {
		aExtr = a.Extractor.Name()
	}
	if b.Extractor != nil {
		bExtr = b.Extractor.Name()
	}

	return cmp.Or(
		cmp.Compare(aLoc, bLoc),
		cmp.Compare(a.Name, b.Name),
		cmp.Compare(a.Version, b.Version),
		cmp.Compare(aExtr, bExtr),
	) < 0
}
