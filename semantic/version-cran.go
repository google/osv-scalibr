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
	"strings"
)

// cranVersion is the representation of a version of a package that is held
// in the CRAN ecosystem (https://cran.r-project.org/).
//
// A version is a sequence of at least two non-negative integers separated by
// either a period or a dash.
//
// See https://astrostatistics.psu.edu/su07/R/html/base/html/package_version.html
type cranVersion struct {
	components components
}

func (v cranVersion) compare(w cranVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	// versions are only equal if they also have the same number of components,
	// otherwise the longer one is considered greater
	if len(v.components) == len(w.components) {
		return 0
	}

	if len(v.components) > len(w.components) {
		return 1
	}

	return -1
}

func (v cranVersion) CompareStr(str string) (int, error) {
	w, err := parseCRANVersion(str)

	if err != nil {
		return 0, err
	}

	return v.compare(w), nil
}

func parseCRANVersion(str string) (cranVersion, error) {
	// for now, treat an empty version string as valid
	if str == "" {
		return cranVersion{}, nil
	}

	// dashes and periods have the same weight, so we can just normalize to periods
	parts := strings.Split(strings.ReplaceAll(str, "-", "."), ".")

	comps := make(components, 0, len(parts))

	for _, s := range parts {
		v, ok := new(big.Int).SetString(s, 10)

		if !ok {
			return cranVersion{}, fmt.Errorf("%w: '%s' is not allowed", ErrInvalidVersion, str)
		}

		comps = append(comps, v)
	}

	return cranVersion{comps}, nil
}
