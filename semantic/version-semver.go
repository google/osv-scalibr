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
	"strings"
)

// Removes build metadata from the given string if present, per semver v2
//
// See https://semver.org/spec/v2.0.0.html#spec-item-10
func removeBuildMetadata(str string) string {
	parts := strings.Split(str, "+")

	return parts[0]
}

func compareBuildComponents(a, b string) int {
	// https://semver.org/spec/v2.0.0.html#spec-item-10
	a = removeBuildMetadata(a)
	b = removeBuildMetadata(b)

	// the spec doesn't explicitly say "don't include the hyphen in the compare"
	// but it's what node-semver does so for now let's go with that...
	a = strings.TrimPrefix(a, "-")
	b = strings.TrimPrefix(b, "-")

	// versions with a prerelease are considered less than those without
	// https://semver.org/spec/v2.0.0.html#spec-item-9
	if a == "" && b != "" {
		return +1
	}
	if a != "" && b == "" {
		return -1
	}

	return compareSemverBuildComponents(
		strings.Split(a, "."),
		strings.Split(b, "."),
	)
}

func compareSemverBuildComponents(a, b []string) int {
	minComponentLength := min(len(a), len(b))

	var compare int

	for i := range minComponentLength {
		ai, aErr := convertToBigInt(a[i])
		bi, bErr := convertToBigInt(b[i])

		switch {
		// 1. Identifiers consisting of only digits are compared numerically.
		case aErr == nil && bErr == nil:
			compare = ai.Cmp(bi)
		// 2. Identifiers with letters or hyphens are compared lexically in ASCII sort order.
		case aErr != nil && bErr != nil:
			compare = strings.Compare(a[i], b[i])
		// 3. Numeric identifiers always have lower precedence than non-numeric identifiers.
		case aErr == nil:
			compare = -1
		default:
			compare = +1
		}

		if compare != 0 {
			if compare > 0 {
				return 1
			}

			return -1
		}
	}

	// 4. A larger set of pre-release fields has a higher precedence than a smaller set,
	//    if all the preceding identifiers are equal.
	if len(a) > len(b) {
		return +1
	}
	if len(a) < len(b) {
		return -1
	}

	return 0
}

type semverVersion struct {
	semverLikeVersion
}

func parseSemverVersion(str string) semverVersion {
	return semverVersion{parseSemverLikeVersion(str, 3)}
}

func (v semverVersion) compare(w semverVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}

	return compareBuildComponents(v.Build, w.Build)
}

func (v semverVersion) CompareStr(str string) (int, error) {
	return v.compare(parseSemverVersion(str)), nil
}
