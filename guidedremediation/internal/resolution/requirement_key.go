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

package resolution

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/npm"
)

// MakeRequirementKey constructs an ecosystem-specific RequirementKey from the given RequirementVersion.
func MakeRequirementKey(requirement resolve.RequirementVersion) manifest.RequirementKey {
	switch requirement.System {
	case resolve.NPM:
		return npm.MakeRequirementKey(requirement)
	case resolve.Maven:
		return maven.MakeRequirementKey(requirement)
	case resolve.PyPI, resolve.UnknownSystem:
		fallthrough
	default:
		return requirement.PackageKey
	}
}
