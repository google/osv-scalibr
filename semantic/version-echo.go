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
	"regexp"
	"strconv"
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
