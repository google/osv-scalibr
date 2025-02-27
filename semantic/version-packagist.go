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
	"regexp"
	"strconv"
	"strings"
)

var (
	packagistVersionSeperatorFinder = regexp.MustCompile(`[-_+]`)
	packagistNonDigitToDigitFinder  = regexp.MustCompile(`([^\d.])(\d)`)
	packagistDigitToNonDigitFinder  = regexp.MustCompile(`(\d)([^\d.])`)
)

func canonicalizePackagistVersion(v string) string {
	// todo: decide how to handle this - without it, we're 1:1 with the native
	//   PHP version_compare function, but composer removes it; arguably this
	//   should be done before the version is passed in (by the dev), except
	//   the ecosystem is named "Packagist" not "php version_compare", though
	//   packagist itself doesn't seem to enforce this (its composer that does
	//   the trimming...)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")

	v = packagistVersionSeperatorFinder.ReplaceAllString(v, ".")
	v = packagistNonDigitToDigitFinder.ReplaceAllString(v, "$1.$2")
	v = packagistDigitToNonDigitFinder.ReplaceAllString(v, "$1.$2")

	return v
}

func weighPackagistBuildCharacter(str string) int {
	if strings.HasPrefix(str, "RC") {
		return 3
	}

	specials := []string{"dev", "a", "b", "rc", "#", "p"}

	for i, special := range specials {
		if strings.HasPrefix(str, special) {
			return i
		}
	}

	return 0
}

func comparePackagistSpecialVersions(a, b string) int {
	av := weighPackagistBuildCharacter(a)
	bv := weighPackagistBuildCharacter(b)

	if av > bv {
		return 1
	} else if av < bv {
		return -1
	}

	return 0
}

func comparePackagistComponents(a, b []string) int {
	minLength := min(len(a), len(b))

	var compare int

	for i := range minLength {
		ai, aErr := convertToBigInt(a[i])
		bi, bErr := convertToBigInt(b[i])

		switch {
		case aErr == nil && bErr == nil:
			compare = ai.Cmp(bi)
		case aErr != nil && bErr != nil:
			compare = comparePackagistSpecialVersions(a[i], b[i])
		case aErr == nil:
			compare = comparePackagistSpecialVersions("#", b[i])
		default:
			compare = comparePackagistSpecialVersions(a[i], "#")
		}

		if compare != 0 {
			if compare > 0 {
				return 1
			}

			return -1
		}
	}

	if len(a) > len(b) {
		next := a[len(b)]

		if _, err := strconv.Atoi(next); err == nil {
			return 1
		}

		return comparePackagistComponents(a[len(b):], []string{"#"})
	}

	if len(a) < len(b) {
		next := b[len(a)]

		if _, err := strconv.Atoi(next); err == nil {
			return -1
		}

		return comparePackagistComponents([]string{"#"}, b[len(a):])
	}

	return 0
}

type packagistVersion struct {
	Original   string
	Components []string
}

func parsePackagistVersion(str string) packagistVersion {
	return packagistVersion{
		str,
		strings.Split(canonicalizePackagistVersion(str), "."),
	}
}

func (v packagistVersion) compare(w packagistVersion) int {
	return comparePackagistComponents(v.Components, w.Components)
}

func (v packagistVersion) CompareStr(str string) (int, error) {
	return v.compare(parsePackagistVersion(str)), nil
}
