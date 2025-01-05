package semantic

import (
	"math/big"
)

type Version interface {
	// CompareStr returns an integer representing the sort order of the given string
	// when parsed as the concrete Version relative to the subject Version.
	//
	// The result will be 0 if v == w, -1 if v < w, or +1 if v > w.
	//
	// An error is returned if the given string is not a valid Version, with "valid"
	// being dependent on the underlying ecosystem of the concrete Version.
	CompareStr(str string) (int, error)
}

type components []*big.Int

func (components *components) Fetch(n int) *big.Int {
	if len(*components) <= n {
		return big.NewInt(0)
	}

	return (*components)[n]
}

func (components *components) Cmp(b components) int {
	numberOfComponents := max(len(*components), len(b))

	for i := range numberOfComponents {
		diff := components.Fetch(i).Cmp(b.Fetch(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}
