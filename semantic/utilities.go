package semantic

import (
	"fmt"
	"math/big"
)

// convertToBigInt attempts to convert the given str to a big.Int,
// returning an error if the conversion fails.
//
// For convenience, it also returns a boolean indicating whether the given
// string was a number or not, which can be useful when the string not being
// a number is actually possible.
func convertToBigInt(str string) (res *big.Int, err error, isNumber bool) {
	i, ok := new(big.Int).SetString(str, 10)

	if !ok {
		return nil, fmt.Errorf("%w: failed to convert %s to a number", ErrInvalidVersion, str), false
	}

	return i, nil, true
}

func fetch(slice []string, i int, def string) string {
	if len(slice) <= i {
		return def
	}

	return slice[i]
}
