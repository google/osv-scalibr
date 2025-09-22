// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

// isASCIIDigit returns true if the given rune is an ASCII digit.
//
// Unicode digits are not considered ASCII digits by this function.
func isASCIIDigit(c rune) bool {
	return c >= 48 && c <= 57
}

// isASCIILetter returns true if the given rune is an ASCII letter.
//
// Unicode letters are not considered ASCII letters by this function.
func isASCIILetter(c rune) bool {
	return (c >= 65 && c <= 90) || (c >= 97 && c <= 122)
}
