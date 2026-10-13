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
	"regexp"
	"strconv"
	"strings"
)

// echoBuildRe matches Echo's `+echo.N` build suffix.
var echoBuildRe = regexp.MustCompile(`\+echo\.(\d+)`)

// echoBuildNumber returns the `+echo.N` build number of the given version,
// or 0 if it does not have one.
func echoBuildNumber(str string) int {
	match := echoBuildRe.FindStringSubmatch(str)
	if match == nil {
		return 0
	}

	n, err := strconv.Atoi(match[1])
	if err != nil {
		return 0
	}

	return n
}

// EchoVersion is the representation of a version in the Echo ecosystem.
//
// Echo is a Debian-derived distribution that also publishes secured builds of
// packages from other ecosystems, named by a suffix on the ecosystem string:
//
//	Echo        - OS packages (dpkg versioning)
//	Echo:PyPI   - Python packages (PEP 440 versioning)
//	Echo:Maven  - Maven packages (Maven versioning)
//	Echo:npm    - npm packages (SemVer versioning)
type EchoVersion struct {
	inner  Version
	suffix string
	build  int
}

var _ Version = EchoVersion{}

// ParseEchoVersion parses the given string as an Echo version, using the
// versioning rules of the ecosystem named by suffix.
//
// An unknown suffix is treated as Echo's own OS packages, matching how OSV.dev
// resolves the Echo ecosystem.
func ParseEchoVersion(str string, suffix string) (EchoVersion, error) {
	v := EchoVersion{suffix: strings.ToLower(suffix)}

	var err error

	switch v.suffix {
	case "pypi":
		v.inner, err = ParsePyPIVersion(str)
	case "maven":
		v.inner = ParseMavenVersion(str)
	case "npm":
		// SemVer excludes build metadata from precedence, so the build number is
		// kept to tie-break on below. PyPI and Maven order it natively.
		v.inner = ParseSemverVersion(str)
		v.build = echoBuildNumber(str)
	default:
		v.suffix = ""
		v.inner, err = ParseDebianVersion(str)
	}

	if err != nil {
		return EchoVersion{}, err
	}

	return v, nil
}

func (v EchoVersion) compare(w EchoVersion) (int, error) {
	if v.suffix != w.suffix {
		return 0, ErrNotSameEcosystem
	}

	diff, err := v.inner.Compare(w.inner)
	if err != nil || diff != 0 {
		return diff, err
	}

	switch {
	case v.build < w.build:
		return -1, nil
	case v.build > w.build:
		return +1, nil
	default:
		return 0, nil
	}
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
	w, err := ParseEchoVersion(str, v.suffix)
	if err != nil {
		return 0, err
	}

	return v.compare(w)
}
