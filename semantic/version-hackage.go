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
	"fmt"
	"strings"
)

// HackageVersion is the representation of a version of a package that is held
// in the Hackage ecosystem.
//
// See https://hackage-content.haskell.org/package/Cabal-syntax-3.16.1.0/docs/Distribution-Types-Version.html
type HackageVersion struct {
	semverLikeVersion
}

var _ Version = HackageVersion{}

func (v HackageVersion) compare(w HackageVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.build), strings.ToLower(w.build))
}

// Compare compares the given version to the receiver.
func (v HackageVersion) Compare(w Version) (int, error) {
	if w, ok := w.(HackageVersion); ok {
		return v.compare(w), nil
	}
	return 0, ErrNotSameEcosystem
}

// CompareStr compares the given string to the receiver.
func (v HackageVersion) CompareStr(str string) (int, error) {
	w, err := ParseHackageVersion(str)

	if err != nil {
		return 0, err
	}

	if diff := v.compare(w); diff != 0 {
		return diff, nil
	}

	if len(v.components) > len(w.components) {
		return +1, nil
	}
	if len(v.components) < len(w.components) {
		return -1, nil
	}

	return 0, nil
}

// ParseHackageVersion parses the given string as a Hackage version.
func ParseHackageVersion(str string) (HackageVersion, error) {
	v := HackageVersion{parseSemverLikeVersion(str, -1)}

	// this is technically possible since we're using the "semver-like" parser
	if v.build != "" {
		return HackageVersion{}, fmt.Errorf("%w: Hackage versions cannot contain a build version", ErrInvalidVersion)
	}

	return v, nil
}
