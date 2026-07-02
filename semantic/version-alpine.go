// Copyright 2026 Google LLC
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
	"cmp"
	"math/big"
	"regexp"
	"strings"
)

var (
	alpineNumberComponentsFinder = regexp.MustCompile(`^([\d.]*)`)
	alpineLetterSectionFinder    = regexp.MustCompile(`^([a-z]\d+)*([a-z]\d*)`)
	alpineSuffixesFinder         = regexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)`)
	alpineHashFinder             = regexp.MustCompile(`^~([0-9a-f]+)`)
	alpineBuildComponentFinder   = regexp.MustCompile(`^-r(\d*)`)
)

type alpineNumberComponent struct {
	original   string
	value      *big.Int
	index      int
	isTrailing bool
}

func (anc alpineNumberComponent) Cmp(b alpineNumberComponent) int {
	// For components after the first, use string comparison if either has a leading zero.
	if anc.index != 0 && b.index != 0 {
		if anc.value == nil {
			if b.value == nil {
				if anc.isTrailing && !b.isTrailing {
					return -1
				}
				if !anc.isTrailing && b.isTrailing {
					return 1
				}
				return 0
			}
			if anc.isTrailing {
				return -1
			}
			if b.value.Cmp(big.NewInt(0)) == 0 {
				return 1 // nil > 0
			}
			return -1 // nil < 1
		}

		if b.value == nil {
			if b.isTrailing {
				return 1
			}
			if anc.value.Cmp(big.NewInt(0)) == 0 {
				return -1 // 0 < nil
			}
			return 1 // 1 > nil
		}

		if (len(anc.original) > 0 && anc.original[0] == '0') || (len(b.original) > 0 && b.original[0] == '0') {
			return strings.Compare(anc.original, b.original)
		}
	}

	return anc.value.Cmp(b.value)
}

type alpineSuffix struct {
	// the weight of this suffix for sorting, and implicitly what actual string it is:
	//   *alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
	weight int
	// the number value of this suffix component
	number *big.Int
}

// weights the given suffix string based on the sort order of official supported suffixes.
//
// this is expected to be _just_ the suffix "string" i.e. it should not start with a "_"
// or have any trailing numbers.
func weightAlpineSuffixString(suffixStr string) int {
	// "p" is omitted since it's the highest suffix, so it will be the final return
	supported := []string{"alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg"}

	for i, s := range supported {
		if suffixStr == s {
			return i
		}
	}

	// if we didn't match a support suffix already, then we're "p" which
	// has the highest weight as our parser only captures valid suffixes
	return len(supported)
}

type alpineLetterComponent struct {
	letter string
	number *big.Int
}

type alpineComponentType int

const (
	componentNumeric alpineComponentType = iota
	componentLetter
	componentSuffix
	componentHash
	componentBuild
)

// AlpineVersion represents a version of an Alpine package.
//
// According to https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd#package-info-metadata
//
// Currently the APK version specification is as follows:
// *number{.number}...{letter}{\_suffix{number}}...{~hash}{-r#}*
//
// Each *number* component is a sequence of digits (0-9).
//
// The *letter* portion can follow only after end of all the numeric
// version components. The *letter* is a single lower case letter (a-z).
//
// Optionally one or more *\_suffix{number}* components can follow.
// The list of valid suffixes (and their sorting order) is:
// *alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*.
//
// This can be followed with an optional *{~hash}* to indicate a commit
// hash from where it was built. This can be any length string of
// lower case hexadecimal digits (0-9a-f).
//
// Finally an optional package build component *-r{number}* can follow.
//
// The above doesn't quite capture handling of 'invalid' versions, observing the behaviour
// on Alpine v10 (apk-tools 2.10.6):
//   - the *letter* component is actually {letter}{number}* and may repeat
//     e.g. 1.0a9b10c11_pre1
//   - versions are compared up to the first invalid token, and the invalid remainder is not compared
//     e.g. 1.0apple = 1.0abc
//   - a version with an invalid version is considered greater than the same version without one
//     e.g. 1.0a < 1.0a_invalid
type AlpineVersion struct {
	// the original string that was parsed
	original string
	// whether the version was found to be invalid while parsing
	invalid bool
	// the remainder of the string after parsing has been completed
	remainder string
	// the last component successfully parsed before the remainder
	lastComponent alpineComponentType
	// slice of number components which can be compared in a semver-like manner
	components []alpineNumberComponent
	// optional 'letter' components
	letter []alpineLetterComponent
	// slice of one or more suffixes, prefixed with "_" and optionally followed by a number.
	//
	// supported suffixes and their sort order are:
	//	*alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
	suffixes []alpineSuffix
	// optional commit hash made up of any number of lower case hexadecimal digits (0-9a-f)
	hash string
	// prefixed with "-r{number}"
	buildComponent *big.Int
}

var _ Version = AlpineVersion{}

func (v AlpineVersion) compareComponents(w AlpineVersion) int {
	minLen := min(len(v.components), len(w.components))

	for i := range minLen {
		if diff := v.components[i].Cmp(w.components[i]); diff != 0 {
			return diff
		}
	}

	return cmp.Compare(len(v.components), len(w.components))
}

func (v AlpineVersion) compareLetters(w AlpineVersion) int {
	numberOfLetters := min(len(v.letter), len(w.letter))

	for i := range numberOfLetters {
		vl, wl := v.letter[i], w.letter[i]
		if diff := strings.Compare(vl.letter, wl.letter); diff != 0 {
			return diff
		}
		// no number < 0
		if vl.number == nil {
			if wl.number != nil {
				return -1
			}
			continue // both empty
		}
		if wl.number == nil {
			return +1
		}
		if diff := vl.number.Cmp(wl.number); diff != 0 {
			return diff
		}
	}

	return cmp.Compare(len(v.letter), len(w.letter))
}

func (v AlpineVersion) fetchSuffix(n int) alpineSuffix {
	if len(v.suffixes) <= n {
		return alpineSuffix{number: big.NewInt(0), weight: 5}
	}

	return v.suffixes[n]
}

func (as alpineSuffix) Cmp(bs alpineSuffix) int {
	if as.weight > bs.weight {
		return +1
	}
	if as.weight < bs.weight {
		return -1
	}

	return as.number.Cmp(bs.number)
}

func (v AlpineVersion) compareSuffixes(w AlpineVersion) int {
	numberOfSuffixes := max(len(v.suffixes), len(w.suffixes))

	for i := range numberOfSuffixes {
		diff := v.fetchSuffix(i).Cmp(w.fetchSuffix(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}

func (v AlpineVersion) compareBuildComponents(w AlpineVersion) int {
	if v.buildComponent != nil && w.buildComponent != nil {
		if diff := v.buildComponent.Cmp(w.buildComponent); diff != 0 {
			return diff
		}
	}

	return 0
}

func compareNumericJunk(v, w AlpineVersion) (int, bool) {
	if v.remainder != "" && v.lastComponent == componentNumeric && w.remainder == "" {
		if w.lastComponent == componentLetter {
			return 1, true
		}
		if w.lastComponent == componentNumeric {
			if v.remainder == "_" {
				return 1, true
			}
			return -1, true
		}
	}
	return 0, false
}

func compareLetterJunk(v, w AlpineVersion) (int, bool) {
	if v.remainder != "" && v.lastComponent == componentLetter && w.remainder == "" && w.lastComponent == componentLetter {
		return -1, true
	}
	return 0, false
}

func compareFinalRemainders(v, w AlpineVersion) int {
	if v.remainder != "" || w.remainder != "" {
		if v.remainder != "" && w.remainder != "" {
			if v.lastComponent == componentNumeric && w.lastComponent == componentBuild {
				return 1
			}
			if v.lastComponent == componentBuild && w.lastComponent == componentNumeric {
				return -1
			}
			if v.lastComponent == w.lastComponent {
				return 0
			}
		}

		if v.remainder != "" && w.remainder == "" {
			return 1
		}
		if v.remainder == "" && w.remainder != "" {
			return -1
		}
	}

	return 0
}

func (v AlpineVersion) compare(w AlpineVersion) int {
	// note: commit hashes are ignored as we can't properly compare them
	if diff := v.compareComponents(w); diff != 0 {
		return diff
	}

	if diff, ok := compareNumericJunk(v, w); ok {
		return diff
	}
	if diff, ok := compareNumericJunk(w, v); ok {
		return -diff
	}

	if diff := v.compareLetters(w); diff != 0 {
		return diff
	}

	if diff, ok := compareLetterJunk(v, w); ok {
		return diff
	}
	if diff, ok := compareLetterJunk(w, v); ok {
		return -diff
	}

	if diff := v.compareSuffixes(w); diff != 0 {
		return diff
	}

	if diff := v.compareBuildComponents(w); diff != 0 {
		return diff
	}

	return compareFinalRemainders(v, w)
}

// Compare compares the given version to the receiver.
func (v AlpineVersion) Compare(w Version) (int, error) {
	if w, ok := w.(AlpineVersion); ok {
		return v.compare(w), nil
	}
	return 0, ErrNotSameEcosystem
}

// CompareStr compares the given string to the receiver.
func (v AlpineVersion) CompareStr(str string) (int, error) {
	w, err := ParseAlpineVersion(str)

	if err != nil {
		return 0, err
	}

	return v.compare(w), nil
}

// parseAlpineNumberComponents parses the given string into alpineVersion.components
// and then returns the remainder of the string for continued parsing.
//
// Each number component is a sequence of digits (0-9), separated with a ".",
// and with no limit on the value or amount of number components.
//
// This parser must be applied *before* any other parser.
func parseAlpineNumberComponents(v *AlpineVersion, str string) (string, error) {
	sub := alpineNumberComponentsFinder.FindString(str)

	if sub == "" {
		return str, nil
	}

	parts := strings.Split(sub, ".")
	for i, d := range parts {
		if d == "" {
			isTrailing := (i == len(parts)-1)
			v.components = append(v.components, alpineNumberComponent{
				value:      nil,
				index:      i,
				original:   "",
				isTrailing: isTrailing,
			})
			continue
		}

		value, err := convertToBigInt(d)
		if err != nil {
			return "", err
		}

		v.components = append(v.components, alpineNumberComponent{
			value:    value,
			index:    i,
			original: d,
		})
	}

	v.lastComponent = componentNumeric
	return strings.TrimPrefix(str, sub), nil
}

// parseAlpineLetter parses the given string into an alpineVersion.letter
// and then returns the remainder of the string for continued parsing.
//
// This parser must be applied *after* parseAlpineNumberComponents.
func parseAlpineLetter(v *AlpineVersion, str string) (string, error) {
	validPart := alpineLetterSectionFinder.FindString(str)

	if validPart == "" {
		return str, nil
	}

	chunkFinder := regexp.MustCompile(`([a-z])(\d*)`)
	matches := chunkFinder.FindAllStringSubmatch(validPart, -1)

	for _, match := range matches {
		letter := match[1]
		numberStr := match[2]

		var number *big.Int
		if numberStr != "" {
			var err error
			number, err = convertToBigInt(numberStr)
			if err != nil {
				return "", err
			}
		}

		v.letter = append(v.letter, alpineLetterComponent{
			letter: letter,
			number: number,
		})
	}

	v.lastComponent = componentLetter
	return str[len(validPart):], nil
}

// parseAlpineSuffixes parses the given string into alpineVersion.suffixes and
// then returns the remainder of the string for continued parsing.
//
// Suffixes begin with an "_" and may optionally end with a number.
//
// This parser must be applied *after* parseAlpineLetter.
func parseAlpineSuffixes(v *AlpineVersion, str string) (string, error) {
	for _, match := range alpineSuffixesFinder.FindAllStringSubmatch(str, -1) {
		if match[2] == "" {
			match[2] = "0"
		}

		number, err := convertToBigInt(match[2])

		if err != nil {
			return "", err
		}

		v.suffixes = append(v.suffixes, alpineSuffix{
			weight: weightAlpineSuffixString(match[1]),
			number: number,
		})
		v.lastComponent = componentSuffix
		str = strings.TrimPrefix(str, match[0])
	}

	return str, nil
}

// parseAlpineHash parses the given string into alpineVersion.hash and then returns
// the remainder of the string for continued parsing.
//
// The hash is an optional value representing a commit hash, which is a string of
// that starts with a "~" and is followed by any number of lower case hexadecimal
// digits (0-9a-f).
//
// This parser must be applied *after* parseAlpineSuffixes.
func parseAlpineHash(v *AlpineVersion, str string) string {
	v.hash = alpineHashFinder.FindString(str)

	if v.hash != "" {
		v.lastComponent = componentHash
	}

	return strings.TrimPrefix(str, v.hash)
}

// parseAlpineBuildComponent parses the given string into alpineVersion.buildComponent
// and then returns the remainder of the string for continued parsing.
//
// The build component is an optional value at the end of the version string which
// begins with "-r" followed by a number.
//
// This parser must be applied *after* parseAlpineBuildComponent
func parseAlpineBuildComponent(v *AlpineVersion, str string) (string, error) {
	if str == "" {
		return str, nil
	}

	matches := alpineBuildComponentFinder.FindStringSubmatch(str)

	if matches == nil {
		// since this is the last part of parsing, anything other than an empty string
		// must match as a build component or otherwise the version is invalid
		v.invalid = true

		return str, nil
	}

	if matches[1] == "" {
		matches[1] = "0"
	}

	buildComponent, err := convertToBigInt(matches[1])

	if err != nil {
		return "", err
	}

	v.buildComponent = buildComponent

	v.lastComponent = componentBuild
	return strings.TrimPrefix(str, matches[0]), nil
}

// ParseAlpineVersion parses the given string as an Alpine version.
func ParseAlpineVersion(str string) (AlpineVersion, error) {
	var err error

	v := AlpineVersion{original: str, buildComponent: new(big.Int)}

	// 0 vs empty string behaves weirdly, and inconsistently in different components
	// but functionally, adding a leading 0 does not change the version
	// i.e. ".0" == "0.0" == "00.0"
	// Add a 0 to the beginning of the string to handle these cases easier
	str = "0" + str

	if str, err = parseAlpineNumberComponents(&v, str); err != nil {
		return AlpineVersion{}, err
	}

	if str, err = parseAlpineLetter(&v, str); err != nil {
		return AlpineVersion{}, err
	}

	if str, err = parseAlpineSuffixes(&v, str); err != nil {
		return AlpineVersion{}, err
	}

	str = parseAlpineHash(&v, str)

	if str, err = parseAlpineBuildComponent(&v, str); err != nil {
		return AlpineVersion{}, err
	}

	v.remainder = str

	return v, nil
}
