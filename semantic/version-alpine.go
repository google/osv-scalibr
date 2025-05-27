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
	"math/big"
	"regexp"
	"strings"
)

var (
	alpineNumberComponentsFinder     = regexp.MustCompile(`^((\d+)\.?)*`)
	alpineIsFirstCharLowercaseLetter = regexp.MustCompile(`^[a-z]`)
	alpineSuffixesFinder             = regexp.MustCompile(`_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)`)
	alpineHashFinder                 = regexp.MustCompile(`^~([0-9a-f]+)`)
	alpineBuildComponentFinder       = regexp.MustCompile(`^-r(\d*)`)
)

type alpineNumberComponent struct {
	original string
	value    *big.Int
	index    int
}

func (anc alpineNumberComponent) Cmp(b alpineNumberComponent) int {
	// ignore trailing zeros for the first digits in each version
	if anc.index != 0 && b.index != 0 {
		if anc.original[0] == '0' || b.original[0] == '0' {
			return strings.Compare(anc.original, b.original)
		}
	}

	return anc.value.Cmp(b.value)
}

type alpineNumberComponents []alpineNumberComponent

func (components *alpineNumberComponents) Fetch(n int) alpineNumberComponent {
	if len(*components) <= n {
		return alpineNumberComponent{original: "0", value: new(big.Int)}
	}

	return (*components)[n]
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

// alpineVersion represents a version of an Alpine package.
//
// Currently, the APK version specification is as follows:
// *number{.number}...{letter}{\_suffix{number}}...{~hash}{-r#}*
//
// Each *number* component is a sequence of digits (0-9).
//
// The *letter* portion can follow only after end of all the numeric
// version components. The *letter* is a single lower case letter (a-z).
// This can follow one or more *\_suffix{number}* components. The list
// of valid suffixes (and their sorting order) is:
// *alpha*, *beta*, *pre*, *rc*, <no suffix>, *cvs*, *svn*, *git*, *hg*, *p*
//
// This can be follows with an optional *{~hash}* to indicate a commit
// hash from where it was built. This can be any length string of
// lower case hexadecimal digits (0-9a-f).
//
// Finally, an optional package build component *-r{number}* can follow.
//
// Also see https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-package.5.scd#package-info-metadata
type alpineVersion struct {
	// the original string that was parsed
	original string
	// whether the version was found to be invalid while parsing
	invalid bool
	// the remainder of the string after parsing has been completed
	remainder string
	// slice of number components which can be compared in a semver-like manner
	components alpineNumberComponents
	// optional single lower-case letter
	letter string
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

func (v alpineVersion) compareComponents(w alpineVersion) int {
	numberOfComponents := max(len(v.components), len(w.components))

	for i := range numberOfComponents {
		diff := v.components.Fetch(i).Cmp(w.components.Fetch(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}

func (v alpineVersion) compareLetters(w alpineVersion) int {
	if v.letter == "" && w.letter != "" {
		return -1
	}
	if v.letter != "" && w.letter == "" {
		return +1
	}

	return strings.Compare(v.letter, w.letter)
}

func (v alpineVersion) fetchSuffix(n int) alpineSuffix {
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

func (v alpineVersion) compareSuffixes(w alpineVersion) int {
	numberOfSuffixes := max(len(v.suffixes), len(w.suffixes))

	for i := range numberOfSuffixes {
		diff := v.fetchSuffix(i).Cmp(w.fetchSuffix(i))

		if diff != 0 {
			return diff
		}
	}

	return 0
}

func (v alpineVersion) compareBuildComponents(w alpineVersion) int {
	if v.buildComponent != nil && w.buildComponent != nil {
		if diff := v.buildComponent.Cmp(w.buildComponent); diff != 0 {
			return diff
		}
	}

	return 0
}

func (v alpineVersion) compareRemainder(w alpineVersion) int {
	if v.remainder == "" && w.remainder != "" {
		return +1
	}

	if v.remainder != "" && w.remainder == "" {
		return -1
	}

	return 0
}

func (v alpineVersion) compare(w alpineVersion) int {
	// if both versions are invalid, then just use a string compare
	if v.invalid && w.invalid {
		return strings.Compare(v.original, w.original)
	}

	// note: commit hashes are ignored as we can't properly compare them
	if diff := v.compareComponents(w); diff != 0 {
		return diff
	}
	if diff := v.compareLetters(w); diff != 0 {
		return diff
	}
	if diff := v.compareSuffixes(w); diff != 0 {
		return diff
	}
	if diff := v.compareBuildComponents(w); diff != 0 {
		return diff
	}
	if diff := v.compareRemainder(w); diff != 0 {
		return diff
	}

	return 0
}

func (v alpineVersion) CompareStr(str string) (int, error) {
	w, err := parseAlpineVersion(str)

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
func parseAlpineNumberComponents(v *alpineVersion, str string) (string, error) {
	sub := alpineNumberComponentsFinder.FindString(str)

	if sub == "" {
		return str, nil
	}

	for i, d := range strings.Split(sub, ".") {
		// while technically not allowed by the spec, currently apk does not
		// consider it invalid to have a dot that isn't followed by a digit
		if d == "" {
			break
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

	return strings.TrimPrefix(str, sub), nil
}

// parseAlpineLetter parses the given string into an alpineVersion.letter
// and then returns the remainder of the string for continued parsing.
//
// The letter is optional, following after the numeric version components, and
// must be a single lower case letter (a-z).
//
// This parser must be applied *after* parseAlpineNumberComponents.
func parseAlpineLetter(v *alpineVersion, str string) string {
	if alpineIsFirstCharLowercaseLetter.MatchString(str) {
		v.letter = str[:1]
	}

	return strings.TrimPrefix(str, v.letter)
}

// parseAlpineSuffixes parses the given string into alpineVersion.suffixes and
// then returns the remainder of the string for continued parsing.
//
// Suffixes begin with an "_" and may optionally end with a number.
//
// This parser must be applied *after* parseAlpineLetter.
func parseAlpineSuffixes(v *alpineVersion, str string) (string, error) {
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
func parseAlpineHash(v *alpineVersion, str string) string {
	v.hash = alpineHashFinder.FindString(str)

	return strings.TrimPrefix(str, v.hash)
}

// parseAlpineBuildComponent parses the given string into alpineVersion.buildComponent
// and then returns the remainder of the string for continued parsing.
//
// The build component is an optional value at the end of the version string which
// begins with "-r" followed by a number.
//
// This parser must be applied *after* parseAlpineBuildComponent
func parseAlpineBuildComponent(v *alpineVersion, str string) (string, error) {
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

	return strings.TrimPrefix(str, matches[0]), nil
}

func parseAlpineVersion(str string) (alpineVersion, error) {
	var err error

	v := alpineVersion{original: str, buildComponent: new(big.Int)}

	if str, err = parseAlpineNumberComponents(&v, str); err != nil {
		return alpineVersion{}, err
	}

	str = parseAlpineLetter(&v, str)

	if str, err = parseAlpineSuffixes(&v, str); err != nil {
		return alpineVersion{}, err
	}

	str = parseAlpineHash(&v, str)

	if str, err = parseAlpineBuildComponent(&v, str); err != nil {
		return alpineVersion{}, err
	}

	v.remainder = str

	return v, nil
}
