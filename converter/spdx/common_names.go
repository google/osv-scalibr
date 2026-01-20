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

package spdx

import (
	"regexp"
	"sort"
	"strings"
)

// Handle mapping common names like LGPL2 to LGPL-2.0-only etc.

var (
	// conditionally remove hyphen before version number
	minusVersion = regexp.MustCompile("[-]([0-9])")

	// conditionally remove hyphen after version number
	versionMinus = regexp.MustCompile("([0-9])[-]")

	// remove ".0" from end of version number
	trailingZero = regexp.MustCompile("[.]0($|[^.0-9])")

	// turn "-Variant-Name" into initialism "VN"
	trailingInitialism = regexp.MustCompile("[-]([A-Z])[a-z]+($|[^A-Za-z])")

	commonLicenseNameToShortIdentifier map[string]string
)

// mapCommonLicenseNames calculates a map from ill-formed common license names to canonical names.
func mapCommonLicenseNames() map[string]string {
	var commonLicenseNameToShortIdentifier = make(map[string]string)
	sortedCanonical := make([]string, 0, len(canonicalLicenses))
	// sort the canonical licenses so the `"name-only"` version overwrites the `"name"` version.
	for canonical := range canonicalLicenses {
		sortedCanonical = append(sortedCanonical, canonical)
	}
	sort.Strings(sortedCanonical)

	// alreadyPopulated prevents an initialism from clobbering a name
	alreadyPopulated := func(canonical, l string) bool {
		other, ok := commonLicenseNameToShortIdentifier[strings.ToUpper(l)]
		if !ok {
			return false
		}
		// do overwrite "name" with "name-only"
		return canonical != other+"-only"
	}

	for _, canonical := range sortedCanonical {
		// support case-insensitive match
		commonLicenseNameToShortIdentifier[strings.ToUpper(canonical)] = canonical

		base := normalize(strings.ReplaceAll(strings.ReplaceAll(canonical, "-only", ""), "-or-later", "+"))
		// base itself is a match for canonical
		commonLicenseNameToShortIdentifier[strings.ToUpper(base)] = canonical

		for {
			// If the canonical has ver.0.0.0, accept each version with 1 fewer .0's
			l := strings.ToUpper(base)
			for loc := trailingZero.FindAllStringSubmatchIndex(l, -1); loc != nil; loc = trailingZero.FindAllStringSubmatchIndex(l, -1) {
				l = replaceLastGroup(l, loc)
				commonLicenseNameToShortIdentifier[l] = canonical
			}

			// handle potential initialism like "ASWF-Digital-Assets" as "ASWFDA"
			l = makeInitialism(base)
			if l != base {
				if !alreadyPopulated(canonical, l) {
					commonLicenseNameToShortIdentifier[strings.ToUpper(l)] = canonical
				}
				for loc := trailingZero.FindAllStringSubmatchIndex(l, -1); loc != nil; loc = trailingZero.FindAllStringSubmatchIndex(l, -1) {
					l = replaceLastGroup(l, loc)
					// don't overwrite an actual name with an initialism
					if alreadyPopulated(canonical, l) {
						continue
					}
					commonLicenseNameToShortIdentifier[strings.ToUpper(l)] = canonical
				}
			}

			// repeat the above for 1.0- without the dash
			l = versionMinus.ReplaceAllString(base, "$1")
			if l == base {
				l = strings.ReplaceAll(base, "-", "")
				if l == base {
					break
				}
			}
			commonLicenseNameToShortIdentifier[strings.ToUpper(l)] = canonical
			base = l
		}
	}
	return commonLicenseNameToShortIdentifier
}

func replaceLastGroup(l string, locs [][]int) string {
	loc := locs[len(locs)-1]
	return l[:loc[0]] + l[loc[len(loc)-2]:loc[len(loc)-1]] + l[loc[1]:]
}

func normalize(l string) string {
	// turn something like "Apache-2.0" into "Apache2.0"
	return minusVersion.ReplaceAllString(strings.TrimSpace(l), "$1")
}

func makeInitialism(l string) string {
	// turn something like "ASWF-Digital-Assets" into "ASWFDA"
	for locs := trailingInitialism.FindAllStringSubmatchIndex(l, -1); locs != nil; locs = trailingInitialism.FindAllStringSubmatchIndex(l, -1) {
		loc := locs[len(locs)-1]
		l = l[:loc[0]] + l[loc[len(loc)-4]:loc[len(loc)-3]] + l[loc[len(loc)-2]:loc[len(loc)-1]] + l[loc[1]:]
	}
	return l
}

// ShortIdentifier returns the SPDX Short Identifier for the license name and true or an empty string and false.
// see: https://github.com/spdx/license-list-XML/blob/main/DOCS/license-fields.md#b-short-identifier
func ShortIdentifier(l string) (string, bool) {
	if _, ok := canonicalLicenses[l]; ok {
		return l, ok
	}
	l = strings.ToUpper(l)
	if commonLicenseNameToShortIdentifier == nil {
		commonLicenseNameToShortIdentifier = mapCommonLicenseNames()
	}
	if si, ok := commonLicenseNameToShortIdentifier[l]; ok {
		return si, ok
	}
	if si, ok := commonLicenseNameToShortIdentifier[normalize(l)]; ok {
		return si, ok
	}
	return "", false
}
