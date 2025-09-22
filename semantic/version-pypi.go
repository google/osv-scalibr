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
	"regexp"
	"strings"
)

var (
	pypiLocalVersionSplitter = regexp.MustCompile(`[._-]`)
	pypiVersionPartsFinder   = regexp.MustCompile(`(\d+|[a-z]+|\.|-)`)
	// from https://peps.python.org/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions
	pypiVersionFinder = regexp.MustCompile(`^\s*v?(?:(?:(?P<epoch>[0-9]+)!)?(?P<release>[0-9]+(?:\.[0-9]+)*)(?P<pre>[-_\.]?(?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))[-_\.]?(?P<pre_n>[0-9]+)?)?(?P<post>(?:-(?P<post_n1>[0-9]+))|(?:[-_\.]?(?P<post_l>post|rev|r)[-_\.]?(?P<post_n2>[0-9]+)?))?(?P<dev>[-_\.]?(?P<dev_l>dev)[-_\.]?(?P<dev_n>[0-9]+)?)?)(?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?\s*$`)
)

type pyPIVersion struct {
	epoch   *big.Int
	release components
	pre     letterAndNumber
	post    letterAndNumber
	dev     letterAndNumber
	local   []string
	legacy  []string
}

type letterAndNumber struct {
	letter string
	number *big.Int
}

func parseLetterVersion(letter, number string) (letterAndNumber, error) {
	if letter != "" {
		// we consider there to be an implicit 0 in a pre-release
		// if there is not a numeral associated with it
		if number == "" {
			number = "0"
		}

		// we normalize any letters to their lowercase form
		letter = strings.ToLower(letter)

		// we consider some words to be alternative spellings of other words and in
		// those cases we want to normalize the spellings to our preferred spelling
		switch letter {
		case "alpha":
			letter = "a"
		case "beta":
			letter = "b"
		case "c":
			fallthrough
		case "pre":
			fallthrough
		case "preview":
			letter = "rc"
		case "rev":
			fallthrough
		case "r":
			letter = "post"
		}

		num, err := convertToBigInt(number)

		if err != nil {
			return letterAndNumber{}, err
		}

		return letterAndNumber{letter, num}, nil
	}

	if number != "" {
		// we assume if we're given a number but not a letter then this is using
		// the implicit post release syntax (e.g. 1.0-1)
		letter = "post"

		num, err := convertToBigInt(number)

		if err != nil {
			return letterAndNumber{}, err
		}

		return letterAndNumber{letter, num}, nil
	}

	return letterAndNumber{}, nil
}

func parseLocalVersion(local string) (parts []string) {
	for _, part := range pypiLocalVersionSplitter.Split(local, -1) {
		parts = append(parts, strings.ToLower(part))
	}

	return parts
}

func normalizePyPILegacyPart(part string) string {
	switch part {
	case "pre":
		part = "c"
	case "preview":
		part = "c"
	case "-":
		part = "final-"
	case "rc":
		part = "c"
	case "dev":
		part = "@"
	}

	if isASCIIDigit(rune(part[0])) {
		// pad for numeric comparison
		return fmt.Sprintf("%08s", part)
	}

	return "*" + part
}

func parsePyPIVersionParts(str string) (parts []string) {
	splits := pypiVersionPartsFinder.FindAllString(str, -1)
	splits = append(splits, "final")

	for _, part := range splits {
		if part == "" || part == "." {
			continue
		}

		part = normalizePyPILegacyPart(part)

		if strings.HasPrefix(part, "*") {
			if strings.Compare(part, "*final") < 0 {
				for len(parts) > 0 && parts[len(parts)-1] == "*final-" {
					parts = parts[:len(parts)-1]
				}
			}

			for len(parts) > 0 && parts[len(parts)-1] == "00000000" {
				parts = parts[:len(parts)-1]
			}
		}

		parts = append(parts, part)
	}

	return parts
}

func parsePyPILegacyVersion(str string) pyPIVersion {
	parts := parsePyPIVersionParts(str)

	return pyPIVersion{epoch: big.NewInt(-1), legacy: parts}
}

func parsePyPIVersion(str string) (pyPIVersion, error) {
	str = strings.ToLower(str)

	match := pypiVersionFinder.FindStringSubmatch(str)

	if len(match) == 0 {
		return parsePyPILegacyVersion(str), nil
	}

	var version pyPIVersion

	version.epoch = big.NewInt(0)

	if epStr := match[pypiVersionFinder.SubexpIndex("epoch")]; epStr != "" {
		epoch, err := convertToBigInt(epStr)

		if err != nil {
			return pyPIVersion{}, err
		}

		version.epoch = epoch
	}

	for _, r := range strings.Split(match[pypiVersionFinder.SubexpIndex("release")], ".") {
		release, err := convertToBigInt(r)

		if err != nil {
			return pyPIVersion{}, err
		}

		version.release = append(version.release, release)
	}

	pre, err := parseLetterVersion(match[pypiVersionFinder.SubexpIndex("pre_l")], match[pypiVersionFinder.SubexpIndex("pre_n")])

	if err != nil {
		return pyPIVersion{}, err
	}

	version.pre = pre

	post := match[pypiVersionFinder.SubexpIndex("post_n1")]

	if post == "" {
		post = match[pypiVersionFinder.SubexpIndex("post_n2")]
	}

	post2, err := parseLetterVersion(match[pypiVersionFinder.SubexpIndex("post_l")], post)

	if err != nil {
		return pyPIVersion{}, err
	}

	version.post = post2

	dev, err := parseLetterVersion(match[pypiVersionFinder.SubexpIndex("dev_l")], match[pypiVersionFinder.SubexpIndex("dev_n")])

	if err != nil {
		return pyPIVersion{}, err
	}

	version.dev = dev
	version.local = parseLocalVersion(match[pypiVersionFinder.SubexpIndex("local")])

	return version, nil
}

// Compares the epoch segments of each version
func (pv pyPIVersion) compareEpoch(pw pyPIVersion) int {
	return pv.epoch.Cmp(pw.epoch)
}

// Compares the release segments of each version, which considers the numeric value
// of each component in turn; when comparing release segments with different numbers
// of components, the shorter segment is padded out with additional zeros as necessary.
func (pv pyPIVersion) compareRelease(pw pyPIVersion) int {
	return pv.release.Cmp(pw.release)
}

// Checks if this pyPIVersion should apply a sort trick when comparing pre,
// which ensures that i.e. 1.0.dev0 is before 1.0a0.
func (pv pyPIVersion) shouldApplyPreTrick() bool {
	return pv.pre.number == nil && pv.post.number == nil && pv.dev.number != nil
}

// Compares the pre-release segment of each version, which consist of an alphabetical
// identifier for the pre-release phase, along with a non-negative integer value.
//
// Pre-releases for a given release are ordered first by phase (alpha, beta, release
// candidate) and then by the numerical component within that phase.
//
// Versions without a pre-release are sorted after those with one.
func (pv pyPIVersion) comparePre(pw pyPIVersion) int {
	switch {
	case pv.shouldApplyPreTrick() && pw.shouldApplyPreTrick():
		return +0
	case pv.shouldApplyPreTrick():
		return -1
	case pw.shouldApplyPreTrick():
		return +1
	case pv.pre.number == nil && pw.pre.number == nil:
		return +0
	case pv.pre.number == nil:
		return +1
	case pw.pre.number == nil:
		return -1
	default:
		ai := pv.pre.letter[0]
		bi := pw.pre.letter[0]

		if ai > bi {
			return +1
		}
		if ai < bi {
			return -1
		}

		return pv.pre.number.Cmp(pw.pre.number)
	}
}

// Compares the post-release segment of each version.
//
// Post-releases are ordered by their numerical component, immediately following
// the corresponding release, and ahead of any subsequent release.
//
// Versions without a post segment are sorted before those with one.
func (pv pyPIVersion) comparePost(pw pyPIVersion) int {
	switch {
	case pv.post.number == nil && pw.post.number == nil:
		return +0
	case pv.post.number == nil:
		return -1
	case pw.post.number == nil:
		return +1
	default:
		return pv.post.number.Cmp(pw.post.number)
	}
}

// Compares the dev-release segment of each version, which consists of the string
// ".dev" followed by a non-negative integer value.
//
// Developmental releases are ordered by their numerical component, immediately
// before the corresponding release (and before any pre-releases with the same release segment),
// and following any previous release (including any post-releases).
//
// Versions without a development segment are sorted after those with one.
func (pv pyPIVersion) compareDev(pw pyPIVersion) int {
	switch {
	case pv.dev.number == nil && pw.dev.number == nil:
		return +0
	case pv.dev.number == nil:
		return +1
	case pw.dev.number == nil:
		return -1
	default:
		return pv.dev.number.Cmp(pw.dev.number)
	}
}

// Compares the local segment of each version
func (pv pyPIVersion) compareLocal(pw pyPIVersion) int {
	minVersionLength := min(len(pv.local), len(pw.local))

	var compare int

	for i := range minVersionLength {
		ai, aErr := convertToBigInt(pv.local[i])
		bi, bErr := convertToBigInt(pw.local[i])

		switch {
		// If a segment consists entirely of ASCII digits then that section should be considered an integer for comparison purposes
		case aErr == nil && bErr == nil:
			compare = ai.Cmp(bi)
		// If a segment contains any ASCII letters then that segment is compared lexicographically with case insensitivity.
		case aErr != nil && bErr != nil:
			compare = strings.Compare(pv.local[i], pw.local[i])
		// When comparing a numeric and lexicographic segment, the numeric section always compares as greater than the lexicographic segment.
		case aErr == nil:
			compare = +1
		default:
			compare = -1
		}

		if compare != 0 {
			if compare > 0 {
				return 1
			}

			return -1
		}
	}

	// Additionally a local version with a great number of segments will always compare as greater than a local version with fewer segments,
	// as long as the shorter local version’s segments match the beginning of the longer local version’s segments exactly.
	if len(pv.local) > len(pw.local) {
		return +1
	}
	if len(pv.local) < len(pw.local) {
		return -1
	}

	return 0
}

// Compares the legacy segment of each version.
//
// These are versions that predate and are incompatible with PEP 440 - comparing
// is "best effort" since there isn't a strong specification defined, and are
// always considered lower than PEP 440 versions to match current day tooling.
//
// http://peak.telecommunity.com/DevCenter/setuptools#specifying-your-project-s-version
// looks like a good reference, but unsure where it sits in the actual tooling history
func (pv pyPIVersion) compareLegacy(pw pyPIVersion) int {
	if len(pv.legacy) == 0 && len(pw.legacy) == 0 {
		return +0
	}
	if len(pv.legacy) == 0 && len(pw.legacy) != 0 {
		return +1
	}
	if len(pv.legacy) != 0 && len(pw.legacy) == 0 {
		return -1
	}

	return strings.Compare(
		strings.Join(pv.legacy, ""),
		strings.Join(pw.legacy, ""),
	)
}

func pypiCompareVersion(v, w pyPIVersion) int {
	if legacyDiff := v.compareLegacy(w); legacyDiff != 0 {
		return legacyDiff
	}
	if epochDiff := v.compareEpoch(w); epochDiff != 0 {
		return epochDiff
	}
	if releaseDiff := v.compareRelease(w); releaseDiff != 0 {
		return releaseDiff
	}
	if preDiff := v.comparePre(w); preDiff != 0 {
		return preDiff
	}
	if postDiff := v.comparePost(w); postDiff != 0 {
		return postDiff
	}
	if devDiff := v.compareDev(w); devDiff != 0 {
		return devDiff
	}
	if localDiff := v.compareLocal(w); localDiff != 0 {
		return localDiff
	}

	return 0
}

func (pv pyPIVersion) compare(pw pyPIVersion) int {
	return pypiCompareVersion(pv, pw)
}

func (pv pyPIVersion) CompareStr(str string) (int, error) {
	pw, err := parsePyPIVersion(str)

	if err != nil {
		return 0, err
	}

	return pv.compare(pw), nil
}
