package semantic

import (
	"fmt"
	"math/big"
)

// convertToBigInt attempts to convert the given str to a big.Int,
// returning an error if the conversion fails
func convertToBigInt(str string) (*big.Int, error) {
	i, ok := new(big.Int).SetString(str, 10)

	if !ok {
		return nil, fmt.Errorf("%w: failed to convert %s to a number", ErrInvalidVersion, str)
	}

	return i, nil
}

func fetch(slice []string, i int, def string) string {
	if len(slice) <= i {
		return def
	}

	return slice[i]
}
