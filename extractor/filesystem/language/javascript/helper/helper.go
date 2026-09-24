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

// Package helper provides parsing helpers shared by the JavaScript extractors.
package helper

import "strings"

// SplitNPMAlias extracts the real package name and version from an alias-specified version.
//
// e.g. "npm:pkg@^1.2.3" -> name: "pkg", version: "^1.2.3"
//
// If the version is not an alias specifier, the name will be empty and the version unchanged.
func SplitNPMAlias(v string) (name, version string) {
	if r, ok := strings.CutPrefix(v, "npm:"); ok {
		// A leading "@" is the scope of e.g. "@babel/code-frame" rather than the
		// separator before the version, so only split on a later one.
		if i := strings.LastIndex(r, "@"); i > 0 {
			return r[:i], r[i+1:]
		}

		return r, "" // alias with no version specified
	}

	return "", v // not an alias
}
