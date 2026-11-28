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
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// echoBuildRe matches Echo's `+echo.N` build suffix.
var echoBuildRe = regexp.MustCompile(`\+echo\.(\d+)`)

func compareEchoBuildComponents(a, b string) int {
	return cmp.Compare(echoBuildNumber(a), echoBuildNumber(b))
}

// echoBuildNumber returns the `+echo.N` build number (0 if there is none).
func echoBuildNumber(build string) int {
	m := echoBuildRe.FindStringSubmatch(build)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return 0
	}

	return n
}

// EchoVersion is the representation of a version of a package that is held
// in the Echo ecosystem.
type EchoVersion struct {
	ver    Version
	subeco string
}

var _ Version = EchoVersion{}

func isEchoSubecosystem(subeco string) bool {
	return slices.Contains([]string{"PyPI", "Maven", "npm", "NuGet", "Debian"}, subeco)
}

// ParseEchoVersion parses the given string as a Echo version.
func ParseEchoVersion(str string, subeco string) (EchoVersion, error) {
	if !isEchoSubecosystem(subeco) {
		return EchoVersion{}, errors.New("invalid subeco " + subeco)
	}

	ver, err := Parse(str, subeco)

	if err != nil {
		return EchoVersion{}, err
	}

	return EchoVersion{ver: ver, subeco: subeco}, nil
}

func (v EchoVersion) compare(w EchoVersion) (int, error) {
	diff, err := v.ver.Compare(w.ver)

	if err != nil {
		return 0, err
	}

	// if the versions are considered equal, and the (sub)ecosystem has a build
	// component, compare that as "echo.n" takes priority within this ecosystem
	if diff == 0 {
		if v.subeco == "npm" {
			return compareEchoBuildComponents(
				v.ver.(SemverVersion).build,
				w.ver.(SemverVersion).build,
			), nil
		}

		if v.subeco == "NuGet" {
			return compareEchoBuildComponents(
				strings.ToLower(v.ver.(NuGetVersion).build),
				strings.ToLower(w.ver.(NuGetVersion).build),
			), nil
		}
	}

	return diff, nil
}

// Compare compares the given version to the receiver.
func (v EchoVersion) Compare(w Version) (int, error) {
	if w, ok := w.(EchoVersion); ok {
		return v.compare(w)
	}
	return 0, ErrNotSameEcosystem
}

// CompareStr compares the given string to the receiver.
func (v EchoVersion) CompareStr(str string) (int, error) {
	w, err := ParseEchoVersion(str, v.subeco)

	if err != nil {
		return 0, err
	}

	return v.compare(w)
}
