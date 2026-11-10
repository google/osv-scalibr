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

package internal

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/extractor"
)

// DirectDependency holds metadata about direct dependencies of a software package.
type DirectDependency struct {
	// Version is the version of the software package declaring a set of direct dependencies.
	Version resolve.Version
	// Requirements is the set of requested direct dependencies, with version constraints.
	Requirements []resolve.RequirementVersion
}

// NewDirectDependency is a shortcut for creating a DirectDependency from commonly used parameters.
func NewDirectDependency(system resolve.System, pkg *extractor.Package, reqs []resolve.RequirementVersion) *DirectDependency {
	return &DirectDependency{
		Version: resolve.Version{VersionKey: resolve.VersionKey{
			PackageKey:  resolve.PackageKey{System: system, Name: pkg.Name},
			VersionType: resolve.Concrete,
			Version:     pkg.Version,
		}},
		Requirements: reqs,
	}
}

// NewRequirement is a shortcut for creating a RequirementVersion from commonly used parameters.
func NewRequirement(system resolve.System, name, version string) resolve.RequirementVersion {
	return resolve.RequirementVersion{VersionKey: resolve.VersionKey{
		PackageKey:  resolve.PackageKey{System: system, Name: name},
		VersionType: resolve.Requirement,
		Version:     version,
	}}
}
