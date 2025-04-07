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
	"regexp"
	"sort"
	"strings"
)

var (
	mavenDigitToNonDigitTransitionFinder = regexp.MustCompile(`\D\d`)
	mavenNonDigitToDigitTransitionFinder = regexp.MustCompile(`\d\D`)
)

type mavenVersionToken struct {
	prefix string
	value  string
	isNull bool
}

func (vt *mavenVersionToken) qualifierOrder() (int, error) {
	_, err := convertToBigInt(vt.value)

	if err == nil {
		if vt.prefix == "-" {
			return 2, nil
		}
		if vt.prefix == "." {
			return 3, nil
		}
	}

	if vt.prefix == "-" {
		return 1, nil
	}
	if vt.prefix == "." {
		return 0, nil
	}

	return 0, fmt.Errorf("%w: unknown prefix '%s'", ErrInvalidVersion, vt.prefix)
}

func (vt *mavenVersionToken) shouldTrim() bool {
	return vt.value == "0" || vt.value == "" || vt.value == "final" || vt.value == "ga"
}

func (vt *mavenVersionToken) equal(wt mavenVersionToken) bool {
	return vt.prefix == wt.prefix && vt.value == wt.value
}

var keywordOrder = []string{"alpha", "beta", "milestone", "rc", "snapshot", "", "sp"}

func findKeywordOrder(keyword string) int {
	for i, k := range keywordOrder {
		if k == keyword {
			return i
		}
	}

	return len(keywordOrder)
}

func (vt *mavenVersionToken) lessThan(wt mavenVersionToken) (bool, error) {
	// if the prefix is the same, then compare the token:
	if vt.prefix == wt.prefix {
		vv, vErr := convertToBigInt(vt.value)
		wv, wErr := convertToBigInt(wt.value)

		// numeric tokens have the same natural order
		if vErr == nil && wErr == nil {
			return vv.Cmp(wv) == -1, nil
		}

		// The spec is unclear, but according to Maven's implementation, numerics
		// sort after non-numerics, **unless it's a null value**.
		// https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L443
		if vErr == nil && !vt.isNull {
			return false, nil
		}
		if wErr == nil && !wt.isNull {
			return true, nil
		}

		// Non-numeric tokens ("qualifiers") have the alphabetical order, except
		// for the following tokens which come first in _KEYWORD_ORDER.
		//
		// The spec is unclear, but according to Maven's implementation, unknown
		// qualifiers sort after known qualifiers:
		// https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L423
		leftIdx := findKeywordOrder(vt.value)
		rightIdx := findKeywordOrder(wt.value)

		if leftIdx == len(keywordOrder) && rightIdx == len(keywordOrder) {
			// Both are unknown qualifiers. Just do a lexical comparison.
			return vt.value < wt.value, nil
		}

		return leftIdx < rightIdx, nil
	}

	// else ".qualifier" < "-qualifier" < "-number" < ".number"
	return vt.lessThanByQualifier(wt)
}

func (vt *mavenVersionToken) lessThanByQualifier(wt mavenVersionToken) (bool, error) {
	vo, err := vt.qualifierOrder()
	if err != nil {
		return false, err
	}

	wo, err := wt.qualifierOrder()

	if err != nil {
		return false, err
	}

	return vo < wo, nil
}

type mavenVersion struct {
	tokens []mavenVersionToken
}

func (mv mavenVersion) equal(mw mavenVersion) bool {
	if len(mv.tokens) != len(mw.tokens) {
		return false
	}

	for i := range len(mv.tokens) {
		if !mv.tokens[i].equal(mw.tokens[i]) {
			return false
		}
	}

	return true
}

func newMavenNullVersionToken(token mavenVersionToken) (mavenVersionToken, error) {
	if token.prefix == "." {
		value := "0"

		// "sp" is the only qualifier that comes after an empty value, and because
		// of the way the comparator is implemented, we have to express that here
		if token.value == "sp" {
			value = ""
		}

		return mavenVersionToken{".", value, true}, nil
	}
	if token.prefix == "-" {
		return mavenVersionToken{"-", "", true}, nil
	}

	return mavenVersionToken{}, fmt.Errorf("%w: unknown prefix '%s' (value '%s')", ErrInvalidVersion, token.prefix, token.value)
}

func (mv mavenVersion) lessThan(mw mavenVersion) (bool, error) {
	numberOfTokens := max(len(mv.tokens), len(mw.tokens))

	var left mavenVersionToken
	var right mavenVersionToken
	var err error

	for i := range numberOfTokens {
		// the shorter one padded with enough "null" values with matching prefix to
		// have the same length as the longer one. Padded "null" values depend on
		// the prefix of the other version: 0 for '.', "" for '-'
		if i >= len(mv.tokens) {
			left, err = newMavenNullVersionToken(mw.tokens[i])

			if err != nil {
				return false, err
			}
		} else {
			left = mv.tokens[i]
		}

		if i >= len(mw.tokens) {
			right, err = newMavenNullVersionToken(mv.tokens[i])

			if err != nil {
				return false, err
			}
		} else {
			right = mw.tokens[i]
		}

		// continue padding until the versions are no longer equal,
		// or are the same length in components
		if left.equal(right) {
			continue
		}

		return left.lessThan(right)
	}

	return false, nil
}

// Finds every point in a token where it transitions either from a digit to a non-digit or vis versa,
// which should be considered as being separated by a hyphen.
//
// According to Maven's implementation, any non-digit is a "character":
// https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L627
func mavenFindTransitions(token string) (ints []int) {
	for _, span := range mavenDigitToNonDigitTransitionFinder.FindAllStringIndex(token, -1) {
		ints = append(ints, span[0]+1)
	}

	for _, span := range mavenNonDigitToDigitTransitionFinder.FindAllStringIndex(token, -1) {
		ints = append(ints, span[0]+1)
	}

	sort.Ints(ints)

	return ints
}

func splitCharsInclusive(s, chars string) (out []string) {
	for {
		m := strings.IndexAny(s, chars)
		if m < 0 {
			break
		}
		out = append(out, s[:m], s[m:m+1])
		s = s[m+1:]
	}
	out = append(out, s)

	return
}

func newMavenVersion(str string) mavenVersion {
	var tokens []mavenVersionToken

	// The Maven coordinate is split in tokens between dots ('.'), hyphens ('-')
	// and transitions between digits and characters. The prefix is recorded
	// and will have effect on the order.

	// Split and keep the delimiter.
	rawTokens := splitCharsInclusive(str, "-.")

	var prefix string

	for i := 0; i < len(rawTokens); i += 2 {
		if i == 0 {
			// first token has no preceding prefix
			prefix = ""
		} else {
			// preceding prefix
			prefix = rawTokens[i-1]
		}

		transitions := mavenFindTransitions(rawTokens[i])

		// add the last index so that our algorithm for splitting up the current token works.
		transitions = append(transitions, len(rawTokens[i]))

		prevIndex := 0

		for j, transition := range transitions {
			if j > 0 {
				prefix = "-"
			}
			// The spec doesn't say this, but all qualifiers are case-insensitive.
			current := strings.ToLower(rawTokens[i][prevIndex:transition])

			if current == "" {
				// Empty rawTokens are replaced with "0"
				current = "0"
			}

			// Normalize "cr" to "rc" for easier comparison since they are equal in precedence.
			if current == "cr" {
				current = "rc"
			}
			// Also do this for 'ga', 'final' which are equivalent to empty string.
			// "release" is not part of the spec but is implemented by Maven.
			if current == "ga" || current == "final" || current == "release" {
				current = ""
			}

			// the "alpha", "beta" and "milestone" qualifiers can respectively be
			// shortened to "a", "b" and "m" when directly followed by a number.
			if transition != len(rawTokens[i]) {
				if current == "a" {
					current = "alpha"
				}

				if current == "b" {
					current = "beta"
				}

				if current == "m" {
					current = "milestone"
				}
			}

			// remove any leading zeros
			if d, err := convertToBigInt(current); err == nil {
				current = d.String()
			}

			tokens = append(tokens, mavenVersionToken{prefix, current, false})
			prevIndex = transition
		}
	}

	// Then, starting from the end of the version, the trailing "null" values
	// (0, "", "final", "ga") are trimmed.

	i := len(tokens) - 1

	for i > 0 {
		if tokens[i].shouldTrim() {
			tokens = append(tokens[:i], tokens[i+1:]...)
			i--

			continue
		}

		// This process is repeated at each remaining hyphen from end to start
		for i >= 0 && tokens[i].prefix != "-" {
			i--
		}

		i--
	}

	return mavenVersion{tokens}
}
func (mv mavenVersion) compare(w mavenVersion) (int, error) {
	if mv.equal(w) {
		return 0, nil
	}
	if lt, err := mv.lessThan(w); lt || err != nil {
		if err != nil {
			return 0, err
		}

		return -1, nil
	}

	return +1, nil
}

func (mv mavenVersion) CompareStr(str string) (int, error) {
	return mv.compare(parseMavenVersion(str))
}

func parseMavenVersion(str string) mavenVersion {
	return newMavenVersion(str)
}
