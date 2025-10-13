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

type redHatVersion struct {
	epoch   string
	version string
	release string
}

// isOnlyDigits returns true if the given string contains only digits
func isOnlyDigits(str string) bool {
	for _, c := range str {
		if !isASCIIDigit(c) {
			return false
		}
	}
	return true
}

// shouldBeTrimmed checks if the given rune should be trimmed when parsing redHatVersion components
func shouldBeTrimmed(r rune) bool {
	return !isASCIILetter(r) && !isASCIIDigit(r) && r != '~' && r != '^'
}

// compareRedHatComponents compares two components of a redHatVersion in the same
// manner as rpmvercmp(8) does.
func compareRedHatComponents(a, b string) int {
	if a == "" && b != "" {
		return -1
	}
	if a != "" && b == "" {
		return +1
	}

	var ai, bi int

	for {
		// 1. Trim anything that’s not [A-Za-z0-9], a tilde (~), or a caret (^) from the front of both strings.
		for ai < len(a) && shouldBeTrimmed(rune(a[ai])) {
			ai++
		}

		for bi < len(b) && shouldBeTrimmed(rune(b[bi])) {
			bi++
		}

		// 2. If both strings start with a tilde, discard it and move on to the next character.
		aStartsWithTilde := ai < len(a) && a[ai] == '~'
		bStartsWithTilde := bi < len(b) && b[bi] == '~'

		if aStartsWithTilde && bStartsWithTilde {
			ai++
			bi++

			continue
		}

		// 3. If string `a` starts with a tilde and string `b` does not, return -1 (string `a` is older); and the inverse if string `b` starts with a tilde and string `a` does not.
		if aStartsWithTilde {
			return -1
		}
		if bStartsWithTilde {
			return +1
		}

		// 4. If both strings start with a caret, discard it and move on to the next character.
		aStartsWithCaret := ai < len(a) && a[ai] == '^'
		bStartsWithCaret := bi < len(b) && b[bi] == '^'

		if aStartsWithCaret && bStartsWithCaret {
			ai++
			bi++

			continue
		}

		// 5. if string `a` starts with a caret and string `b` does not, return -1 (string `a` is older) unless string `b` has reached zero length, in which case return +1 (string `a` is newer); and the inverse if string `b` starts with a caret and string `a` does not.
		if aStartsWithCaret {
			if bi == len(b) {
				return +1
			}

			return -1
		}
		if bStartsWithCaret {
			if ai == len(a) {
				return -1
			}

			return +1
		}

		// 6. End the loop if either string has reached zero length.
		if ai == len(a) || bi == len(b) {
			break
		}

		// 7. If the first character of `a` is a digit, pop the leading chunk of continuous digits from each string (which may be "" for `b` if only one `a` starts with digits). If `a` begins with a letter, do the same for leading letters.
		isDigit := isASCIIDigit(rune(a[ai]))

		var isExpectedRunType func(r rune) bool
		if isDigit {
			isExpectedRunType = isASCIIDigit
		} else {
			isExpectedRunType = isASCIILetter
		}

		var as, bs string

		for _, c := range a[ai:] {
			if !isExpectedRunType(c) {
				break
			}

			as += string(c)
			ai++
		}

		for _, c := range b[bi:] {
			if !isExpectedRunType(c) {
				break
			}

			bs += string(c)
			bi++
		}

		// 8. If the segment from `b` had 0 length, return 1 if the segment from `a` was numeric, or -1 if it was alphabetic. The logical result of this is that if `a` begins with numbers and `b` does not, `a` is newer (return 1). If `a` begins with letters and `b` does not, then `a` is older (return -1). If the leading character(s) from `a` and `b` were both numbers or both letters, continue on.
		if bs == "" {
			if isDigit {
				return +1
			}

			return -1
		}

		// 9. If the leading segments were both numeric, discard any leading zeros and whichever one is longer wins. If `a` is longer than `b` (without leading zeroes), return 1, and vice versa. If they’re of the same length, continue on.
		if isDigit {
			as = strings.TrimLeft(as, "0")
			bs = strings.TrimLeft(bs, "0")

			if len(as) > len(bs) {
				return +1
			}
			if len(as) < len(bs) {
				return -1
			}
		}

		// 10. compare the leading segments with strcmp() (or <=> in Ruby). If that returns a non-zero value, then return that value. Else continue to the next iteration of the loop.
		if diff := strings.Compare(as, bs); diff != 0 {
			return diff
		}
	}

	// If the loop ended (nothing has been returned yet, either both strings are totally the same or they’re the same up to the end of one of them, like with “1.2.3” and “1.2.3b”), then the longest wins - if what’s left of a is longer than what’s left of b, return 1. Vice-versa for if what’s left of b is longer than what’s left of a. And finally, if what’s left of them is the same length, return 0.
	al := len(a) - ai
	bl := len(b) - bi

	if al > bl {
		return +1
	}
	if al < bl {
		return -1
	}

	return 0
}

func (v redHatVersion) compare(w redHatVersion) int {
	if diff := compareRedHatComponents(v.epoch, w.epoch); diff != 0 {
		return diff
	}
	if diff := compareRedHatComponents(v.version, w.version); diff != 0 {
		return diff
	}
	if diff := compareRedHatComponents(v.release, w.release); diff != 0 {
		return diff
	}

	return 0
}

func (v redHatVersion) CompareStr(str string) (int, error) {
	return v.compare(parseRedHatVersion(str)), nil
}

// parseRedHatVersion parses a Red Hat version into a redHatVersion struct.
//
// A Red Hat version contains the following components:
// - epoch, represented as "e"
// - version, represented as "v"
// - release, represented as "r"
//
// When all components are present, the version is represented as "e:v-r",
// though only the version is actually required.
func parseRedHatVersion(str string) redHatVersion {
	epoch, vr, hasColon := strings.Cut(str, ":")

	// if there's not a colon, or the "epoch" value has characters other than digits,
	// then the string does not have an epoch value
	if !hasColon || !isOnlyDigits(epoch) {
		vr = str
		epoch = ""
	}

	version, release, hasRelease := strings.Cut(vr, "-")

	if hasRelease {
		release = "-" + release
	}

	if epoch == "" {
		epoch = "0"
	}

	return redHatVersion{epoch, version, release}
}
