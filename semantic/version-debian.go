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
	"strings"
)

func splitAround(s string, sep string, reverse bool) (string, string) {
	var i int

	if reverse {
		i = strings.LastIndex(s, sep)
	} else {
		i = strings.Index(s, sep)
	}

	if i == -1 {
		return s, ""
	}

	return s[:i], s[i+1:]
}

func splitDebianDigitPrefix(str string) (*big.Int, string, error) {
	// find the index of the first non-digit in the string, which is the end of the prefix
	i := strings.IndexFunc(str, func(c rune) bool {
		return c < 48 || c > 57
	})

	if i == 0 || str == "" {
		return big.NewInt(0), str, nil
	}

	if i == -1 {
		i = len(str)
	}

	digit, err := convertToBigInt(str[:i])

	if err != nil {
		return nil, "", err
	}

	return digit, str[i:], nil
}

func splitDebianNonDigitPrefix(str string) (string, string) {
	// find the index of the first digit in the string, which is the end of the prefix
	i := strings.IndexAny(str, "0123456789")

	if i == 0 || str == "" {
		return "", str
	}

	if i == -1 {
		i = len(str)
	}

	return str[:i], str[i:]
}

func weighDebianChar(char string) int {
	// tilde and empty take precedent
	if char == "~" {
		return 1
	}
	if char == "" {
		return 2
	}

	c := int(char[0])

	// all the letters sort earlier than all the non-letters
	if c < 65 || (c > 90 && c < 97) || c > 122 {
		c += 122
	}

	return c
}

func compareDebianVersions(a, b string) (int, error) {
	var ap, bp string
	var adp, bdp *big.Int
	var err error

	// based off: https://man7.org/linux/man-pages/man7/deb-version.7.html
	for a != "" || b != "" {
		ap, a = splitDebianNonDigitPrefix(a)
		bp, b = splitDebianNonDigitPrefix(b)

		// First the initial part of each string consisting entirely of
		// non-digit characters is determined...
		if ap != bp {
			apSplit := strings.Split(ap, "")
			bpSplit := strings.Split(bp, "")

			for i := range max(len(ap), len(bp)) {
				aw := weighDebianChar(fetch(apSplit, i, ""))
				bw := weighDebianChar(fetch(bpSplit, i, ""))

				if aw < bw {
					return -1, nil
				}
				if aw > bw {
					return +1, nil
				}
			}
		}

		// Then the initial part of the remainder of each string which
		// consists entirely of digit characters is determined....
		adp, a, err = splitDebianDigitPrefix(a)

		if err != nil {
			return 0, err
		}

		bdp, b, err = splitDebianDigitPrefix(b)

		if err != nil {
			return 0, err
		}

		if diff := adp.Cmp(bdp); diff != 0 {
			return diff, nil
		}
	}

	return 0, nil
}

type debianVersion struct {
	epoch    *big.Int
	upstream string
	revision string
}

func (v debianVersion) compare(w debianVersion) (int, error) {
	if diff := v.epoch.Cmp(w.epoch); diff != 0 {
		return diff, nil
	}
	if diff, err := compareDebianVersions(v.upstream, w.upstream); diff != 0 || err != nil {
		if err != nil {
			return 0, err
		}

		return diff, nil
	}
	if diff, err := compareDebianVersions(v.revision, w.revision); diff != 0 || err != nil {
		if err != nil {
			return 0, err
		}

		return diff, nil
	}

	return 0, nil
}

func (v debianVersion) CompareStr(str string) (int, error) {
	w, err := parseDebianVersion(str)

	if err != nil {
		return 0, err
	}

	return v.compare(w)
}

func parseDebianVersion(str string) (debianVersion, error) {
	var upstream, revision string

	str = strings.TrimSpace(str)
	epoch := big.NewInt(0)

	if strings.Contains(str, ":") {
		var e string
		var err error
		e, str = splitAround(str, ":", false)

		if epoch, err = convertToBigInt(e); err != nil {
			return debianVersion{}, err
		}
	}

	if strings.Contains(str, "-") {
		upstream, revision = splitAround(str, "-", true)
	} else {
		upstream = str
		revision = "0"
	}

	return debianVersion{epoch, upstream, revision}, nil
}
