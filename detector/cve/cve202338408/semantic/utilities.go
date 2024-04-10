// Copyright 2024 Google LLC
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

func convertToBigIntOrPanic(str string) *big.Int {
	if num, isNumber := convertToBigInt(str); isNumber {
		return num
	}

	panic(fmt.Sprintf("failed to convert %s to a number", str))
}

func convertToBigInt(str string) (*big.Int, bool) {
	i, ok := new(big.Int).SetString(str, 10)

	return i, ok
}

func minInt(x, y int) int {
	if x > y {
		return y
	}

	return x
}

func maxInt(x, y int) int {
	if x < y {
		return y
	}

	return x
}

func fetch(slice []string, i int, def string) string {
	if len(slice) <= i {
		return def
	}

	return slice[i]
}
