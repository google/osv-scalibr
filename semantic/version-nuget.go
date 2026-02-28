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

import "strings"

// NuGetVersion is the representation of a version of a package that is held
// in the NuGet ecosystem.
//
// See https://learn.microsoft.com/en-us/nuget/concepts/package-versioning
type NuGetVersion struct {
	semverLikeVersion
}

var _ Version = NuGetVersion{}

func (v NuGetVersion) compare(w NuGetVersion) int {
	if diff := v.components.Cmp(w.components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.build), strings.ToLower(w.build))
}

// Compare compares the given version to the receiver.
func (v NuGetVersion) Compare(w Version) (int, error) {
	if w, ok := w.(NuGetVersion); ok {
		return v.compare(w), nil
	}
	return 0, ErrNotSameEcosystem
}

// CompareStr compares the given string to the receiver.
func (v NuGetVersion) CompareStr(str string) (int, error) {
	return v.compare(ParseNuGetVersion(str)), nil
}

// ParseNuGetVersion parses the given string as a NuGet version.
func ParseNuGetVersion(str string) NuGetVersion {
	return NuGetVersion{parseSemverLikeVersion(str, 4)}
}
