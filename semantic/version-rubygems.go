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

func canonicalizeRubyGemVersion(str string) string {
	res := ""

	checkPrevious := false
	previousWasDigit := true

	for _, c := range str {
		if c == 46 {
			checkPrevious = false
			res += "."

			continue
		}

		isDigit := isASCIIDigit(c)

		if checkPrevious && previousWasDigit != isDigit {
			res += "."
		}

		res += string(c)

		previousWasDigit = isDigit
		checkPrevious = true
	}

	return res
}

func groupSegments(segs []string) (numbers []string, build []string) {
	for _, seg := range segs {
		_, err := convertToBigInt(seg)

		if len(build) > 0 || err != nil {
			build = append(build, seg)

			continue
		}

		numbers = append(numbers, seg)
	}

	return numbers, build
}

func removeZeros(segs []string) []string {
	i := len(segs) - 1

	for i >= 0 {
		if segs[i] != "0" {
			i++

			break
		}

		i--
	}

	return segs[:max(i, 0)]
}

func canonicalSegments(segs []string) (canSegs []string) {
	numbers, build := groupSegments(segs)

	return append(removeZeros(numbers), removeZeros(build)...)
}

func compareRubyGemsComponents(a, b []string) int {
	numberOfComponents := max(len(a), len(b))

	for i := range numberOfComponents {
		as := fetch(a, i, "0")
		bs := fetch(b, i, "0")

		ai, aErr := convertToBigInt(as)
		bi, bErr := convertToBigInt(bs)

		switch {
		case aErr == nil && bErr == nil:
			if diff := ai.Cmp(bi); diff != 0 {
				return diff
			}
		case aErr != nil && bErr != nil:
			if diff := strings.Compare(as, bs); diff != 0 {
				return diff
			}
		case aErr == nil:
			return +1
		default:
			return -1
		}
	}

	return 0
}

type rubyGemsVersion struct {
	Original string
	Segments []string
}

func parseRubyGemsVersion(str string) rubyGemsVersion {
	return rubyGemsVersion{
		str,
		canonicalSegments(strings.Split(canonicalizeRubyGemVersion(str), ".")),
	}
}

func (v rubyGemsVersion) compare(w rubyGemsVersion) int {
	return compareRubyGemsComponents(v.Segments, w.Segments)
}

func (v rubyGemsVersion) CompareStr(str string) (int, error) {
	return v.compare(parseRubyGemsVersion(str)), nil
}
