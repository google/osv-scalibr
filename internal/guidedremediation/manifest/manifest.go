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

// Package manifest provides methods for parsing and writing manifest files.
package manifest

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest/maven"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest/npm"
)

// Manifest is the interface for the representation of a manifest file needed for dependency resolution.
type Manifest interface {
	FilePath() string                           // Path to the manifest file on disk
	Root() resolve.Version                      // Version representing this package
	System() resolve.System                     // The System of this manifest
	Requirements() []resolve.RequirementVersion // All direct requirements, including dev
	Groups() map[RequirementKey][]string        // Dependency groups that the imports belong to
	LocalManifests() []Manifest                 // Manifests of local packages
	EcosystemSpecific() any                     // Any ecosystem-specific information needed

	Clone() Manifest // Clone the manifest
}

// RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
// It does not include the version specification.
type RequirementKey any

// MakeRequirementKey constructs an ecosystem-specific RequirementKey from the given RequirementVersion.
func MakeRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	switch requirement.System {
	case resolve.NPM:
		return npm.MakeRequirementKey(requirement)
	case resolve.Maven:
		return maven.MakeRequirementKey(requirement)
	case resolve.UnknownSystem:
		fallthrough
	default:
		return requirement.PackageKey
	}
}
