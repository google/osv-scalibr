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
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/result"
	"github.com/google/osv-scalibr/internal/guidedremediation/remediation/strategy"
)

// Manifest is the interface for the representation of a manifest file needed for dependency resolution.
type Manifest interface {
	FilePath() string                           // Path to the manifest file
	Root() resolve.Version                      // Version representing this package
	System() resolve.System                     // The System of this manifest
	Requirements() []resolve.RequirementVersion // All direct requirements, including dev
	Groups() map[RequirementKey][]string        // Dependency groups that the direct requirements belong to
	LocalManifests() []Manifest                 // Manifests of local packages
	EcosystemSpecific() any                     // Any ecosystem-specific information needed

	PatchRequirement(req resolve.RequirementVersion) error // Patch the requirements to use new requirement.

	Clone() Manifest // Clone the manifest
}

// RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
// It does not include the version specification.
type RequirementKey any

// ReadWriter is the interface for parsing and applying remediation patches to a manifest file.
type ReadWriter interface {
	System() resolve.System
	Read(path string, fsys scalibrfs.FS) (Manifest, error)
	SupportedStrategies() []strategy.Strategy

	// Write writes the manifest after applying the patches to outputPath.
	//
	// original is the manifest without patches. fsys is the FS that the manifest was read from.
	// outputPath is the path on disk (*not* in fsys) to write the entire patched manifest to (this can overwrite the original manifest).
	Write(original Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error
}
