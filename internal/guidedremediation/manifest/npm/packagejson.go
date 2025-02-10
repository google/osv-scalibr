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

// Package npm provides the manifest parsing and writing for the npm package.json format.
package npm

import (
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
)

// RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
type RequirementKey struct {
	resolve.PackageKey
	KnownAs string
}

var _ map[RequirementKey]interface{}

// MakeRequirementKey constructs an npm RequirementKey from the given RequirementVersion.
func MakeRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	// Npm requirements are the uniquely identified by the key in the dependencies fields (which ends up being the path in node_modules)
	// Declaring a dependency in multiple places (dependencies, devDependencies, optionalDependencies) only installs it once at one version.
	// Aliases & non-registry dependencies are keyed on their 'KnownAs' attribute.
	knownAs, _ := requirement.Type.GetAttr(dep.KnownAs)
	return RequirementKey{
		PackageKey: requirement.PackageKey,
		KnownAs:    knownAs,
	}
}
