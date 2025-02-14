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

// Package maven provides the manifest parsing and writing for the Maven pom.xml format.
package maven

import (
	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
)

// RequirementKey is a comparable type that uniquely identifies a package dependency in a manifest.
type RequirementKey struct {
	resolve.PackageKey
	ArtifactType string
	Classifier   string
}

var _ map[RequirementKey]any

// MakeRequirementKey constructs a maven RequirementKey from the given RequirementVersion.
func MakeRequirementKey(requirement resolve.RequirementVersion) RequirementKey {
	// Maven dependencies must have unique groupId:artifactId:type:classifier.
	artifactType, _ := requirement.Type.GetAttr(dep.MavenArtifactType)
	classifier, _ := requirement.Type.GetAttr(dep.MavenClassifier)

	return RequirementKey{
		PackageKey:   requirement.PackageKey,
		ArtifactType: artifactType,
		Classifier:   classifier,
	}
}

// ManifestSpecific is ecosystem-specific information needed for the pom.xml manifest.
type ManifestSpecific struct {
	Parent                 maven.Parent
	Properties             []PropertyWithOrigin         // Properties from the base project
	OriginalRequirements   []DependencyWithOrigin       // Dependencies from the base project
	RequirementsForUpdates []resolve.RequirementVersion // Requirements that we only need for updates
	Repositories           []maven.Repository
}

// PropertyWithOrigin is a maven property with the origin where it comes from.
type PropertyWithOrigin struct {
	maven.Property
	Origin string // Origin indicates where the property comes from
}

// DependencyWithOrigin is a maven dependency with the origin where it comes from.
type DependencyWithOrigin struct {
	maven.Dependency
	Origin string // Origin indicates where the dependency comes from
}
