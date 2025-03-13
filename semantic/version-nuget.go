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

import "strings"

type nuGetVersion struct {
	semverLikeVersion
}

func (v nuGetVersion) compare(w nuGetVersion) int {
	if diff := v.Components.Cmp(w.Components); diff != 0 {
		return diff
	}

	return compareBuildComponents(strings.ToLower(v.Build), strings.ToLower(w.Build))
}

func (v nuGetVersion) CompareStr(str string) (int, error) {
	return v.compare(parseNuGetVersion(str)), nil
}

func parseNuGetVersion(str string) nuGetVersion {
	return nuGetVersion{parseSemverLikeVersion(str, 4)}
}
