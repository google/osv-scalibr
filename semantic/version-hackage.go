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
	"strings"
)

type hackageVersion struct {
	semverLikeVersion
}

func (v hackageVersion) compare(w hackageVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.Build), strings.ToLower(w.Build))
}

func (v hackageVersion) CompareStr(str string) (int, error) {
	w, err := parseHackageVersion(str)

	if err != nil {
		return 0, err
	}

	if diff := v.compare(w); diff != 0 {
		return diff, nil
	}

	if len(v.Components) > len(w.Components) {
		return +1, nil
	}
	if len(v.Components) < len(w.Components) {
		return -1, nil
	}

	return 0, nil
}

func parseHackageVersion(str string) (hackageVersion, error) {
	v := hackageVersion{parseSemverLikeVersion(str, -1)}

	// this is technically possible since we're using the "semver-like" parser
	if v.Build != "" {
		return hackageVersion{}, fmt.Errorf("%w: Hackage versions cannot contain a build version", ErrInvalidVersion)
	}

	return v, nil
}
