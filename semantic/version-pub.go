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

type pubVersion struct {
	semverLikeVersion
}

func (v pubVersion) compare(w pubVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}
	if diff := compareBuildComponents(v.Build, w.Build); diff != 0 {
		return diff
	}

	_, vBuild, _ := strings.Cut(v.Build, "+")
	_, wBuild, _ := strings.Cut(w.Build, "+")

	return strings.Compare(vBuild, wBuild)
}

func (v pubVersion) CompareStr(str string) (int, error) {
	w := parsePubVersion(str)

	return v.compare(w), nil
}

func parsePubVersion(str string) pubVersion {
	return pubVersion{parseSemverLikeVersion(str, 3)}
}
