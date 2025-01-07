package semantic

import (
	"fmt"
	"math/big"
)

func convertToBigIntOrPanic(str string) *big.Int {
	if num, err, _ := convertToBigInt(str); err == nil {
		return num
	}

	panic(fmt.Sprintf("failed to convert %s to a number", str))
}

func convertToBigInt(str string) (*big.Int, error, bool) {
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
