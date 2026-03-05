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
	"strings"
)

// PubVersion is the representation of a version of a package that is held
// in the Pub ecosystem.
//
// See https://pub.dev/packages/pub_semver
type PubVersion struct {
	semverLikeVersion
}

var _ Version = PubVersion{}

func (v PubVersion) compare(w PubVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}
	if diff := compareBuildComponents(v.build, w.build); diff != 0 {
		return diff
	}

	_, vBuild, _ := strings.Cut(v.build, "+")
	_, wBuild, _ := strings.Cut(w.build, "+")

	return strings.Compare(vBuild, wBuild)
}

// Compare compares the given version to the receiver.
func (v PubVersion) Compare(w Version) (int, error) {
	if w, ok := w.(PubVersion); ok {
		return v.compare(w), nil
	}
	return 0, ErrNotSameEcosystem
}

// CompareStr compares the given string to the receiver.
func (v PubVersion) CompareStr(str string) (int, error) {
	w := ParsePubVersion(str)

	return v.compare(w), nil
}

// ParsePubVersion parses the given string as a Pub version.
func ParsePubVersion(str string) PubVersion {
	return PubVersion{parseSemverLikeVersion(str, 3)}
}
