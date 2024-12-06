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

// Package semantic provides version comparison.
package semantic

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reSpecChar = regexp.MustCompile(`[-_+]`)
	// Matches a non-digit character followed by a digit.
	reNotDigitDigit = regexp.MustCompile(`([^\d.])(\d)`)
	// Matches a digit followed by a non-digit character.
	reDigitNotDigit = regexp.MustCompile(`(\d)([^\d.])`)
)

func canonicalizePackagistVersion(v string) string {
	// todo: decide how to handle this - without it, we're 1:1 with the native
	//   PHP version_compare function, but composer removes it; arguably this
	//   should be done before the version is passed in (by the dev), except
	//   the ecosystem is named "Packagist" not "php version_compare", though
	//   packagist itself doesn't seem to enforce this (its composer that does
	//   the trimming...)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")

	v = reSpecChar.ReplaceAllString(v, ".")
	v = reNotDigitDigit.ReplaceAllString(v, "$1.$2")
	v = reDigitNotDigit.ReplaceAllString(v, "$1.$2")

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
	minLen := minInt(len(a), len(b))

	var compare int

	for i := range minLen {
		ai, aIsNumber := convertToBigInt(a[i])
		bi, bIsNumber := convertToBigInt(b[i])

		switch {
		case aIsNumber && bIsNumber:
			compare = ai.Cmp(bi)
		case !aIsNumber && !bIsNumber:
			compare = comparePackagistSpecialVersions(a[i], b[i])
		case aIsNumber:
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

// PackagistVersion represents a packagist version.
type PackagistVersion struct {
	Original   string
	Components []string
}

// ParsePackagistVersion parses a packagist version.
func ParsePackagistVersion(str string) PackagistVersion {
	return PackagistVersion{
		str,
		strings.Split(canonicalizePackagistVersion(str), "."),
	}
}

// Compare compares the version with another version.
func (v PackagistVersion) Compare(w PackagistVersion) int {
	return comparePackagistComponents(v.Components, w.Components)
}

// CompareStr compares the version with another version represented as string.
func (v PackagistVersion) CompareStr(str string) int {
	return v.Compare(ParsePackagistVersion(str))
}
