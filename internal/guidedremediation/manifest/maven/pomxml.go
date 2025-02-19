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
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
	"github.com/google/osv-scalibr/internal/mavenutil"
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

type mavenManifest struct {
	filePath     string
	root         resolve.Version
	requirements []resolve.RequirementVersion
	groups       map[manifest.RequirementKey][]string
	specific     ManifestSpecific
}

// FilePath returns the path to the manifest file.
func (m *mavenManifest) FilePath() string {
	return m.filePath
}

// Root returns the Version representing this package.
func (m *mavenManifest) Root() resolve.Version {
	return m.root
}

// System returns the ecosystem of this manifest.
func (m *mavenManifest) System() resolve.System {
	return resolve.Maven
}

// Requirements returns all direct requirements (including dev).
func (m *mavenManifest) Requirements() []resolve.RequirementVersion {
	return m.requirements
}

// Groups returns the dependency groups that the direct requirements belong to.
func (m *mavenManifest) Groups() map[manifest.RequirementKey][]string {
	return m.groups
}

// LocalManifests returns Manifests of any local packages.
func (m *mavenManifest) LocalManifests() []manifest.Manifest {
	return nil
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m *mavenManifest) EcosystemSpecific() any {
	return m.specific
}

// Clone returns a copy of this manifest that is safe to modify.
func (m *mavenManifest) Clone() manifest.Manifest {
	clone := &mavenManifest{
		filePath:     m.filePath,
		root:         m.root,
		requirements: slices.Clone(m.requirements),
		groups:       maps.Clone(m.groups),
		specific: ManifestSpecific{
			Parent:                 m.specific.Parent,
			Properties:             slices.Clone(m.specific.Properties),
			OriginalRequirements:   slices.Clone(m.specific.OriginalRequirements),
			RequirementsForUpdates: slices.Clone(m.specific.RequirementsForUpdates),
			Repositories:           slices.Clone(m.specific.Repositories),
		},
	}
	clone.root.AttrSet = m.root.AttrSet.Clone()

	return clone
}

type readWriter struct {
	*datasource.MavenRegistryAPIClient
}

// GetReadWriter returns a ReadWriter for pom.xml manifest files.
func GetReadWriter(registry string) (manifest.ReadWriter, error) {
	client, err := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: registry, ReleasesEnabled: true})
	if err != nil {
		return nil, err
	}
	return readWriter{MavenRegistryAPIClient: client}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.Maven
}

// Read parses the manifest from the given file.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	ctx := context.Background()
	path = filepath.ToSlash(path)
	f, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var project maven.Project
	if err := datasource.NewMavenDecoder(f).Decode(&project); err != nil {
		return nil, fmt.Errorf("failed to unmarshal project: %w", err)
	}
	properties := buildPropertiesWithOrigins(project, "")
	origRequirements := buildOriginalRequirements(project, "")

	var reqsForUpdates []resolve.RequirementVersion
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		reqsForUpdates = append(reqsForUpdates, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   project.Parent.ProjectKey.Name(),
				},
				// Parent version is a concrete version, but we model parent as dependency here.
				VersionType: resolve.Requirement,
				Version:     string(project.Parent.Version),
			},
			Type: resolve.MavenDepType(maven.Dependency{Type: "pom"}, mavenutil.OriginParent),
		})
	}

	// Empty JDK and ActivationOS indicates merging the default profiles.
	if err := project.MergeProfiles("", maven.ActivationOS{}); err != nil {
		return nil, fmt.Errorf("failed to merge profiles: %w", err)
	}

	// TODO: there may be properties in repo.Releases.Enabled and repo.Snapshots.Enabled
	for _, repo := range project.Repositories {
		if err := r.MavenRegistryAPIClient.AddRegistry(datasource.MavenRegistry{
			URL:              string(repo.URL),
			ID:               string(repo.ID),
			ReleasesEnabled:  repo.Releases.Enabled.Boolean(),
			SnapshotsEnabled: repo.Snapshots.Enabled.Boolean(),
		}); err != nil {
			return nil, fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
		}
	}

	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := mavenutil.MergeParents(ctx, &filesystem.ScanInput{FS: fsys, Path: path}, r.MavenRegistryAPIClient, &project, project.Parent, 1, true); err != nil {
		return nil, fmt.Errorf("failed to merge parents: %w", err)
	}

	// For dependency management imports, the dependencies that imports
	// dependencies from other projects will be replaced by the imported
	// dependencies, so add them to requirements first.
	for _, dep := range project.DependencyManagement.Dependencies {
		if dep.Scope == "import" && dep.Type == "pom" {
			reqsForUpdates = append(reqsForUpdates, makeRequirementVersion(dep, mavenutil.OriginManagement))
		}
	}

	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		return mavenutil.GetDependencyManagement(ctx, r.MavenRegistryAPIClient, groupID, artifactID, version)
	})

	groups := make(map[manifest.RequirementKey][]string)
	requirements := addRequirements([]resolve.RequirementVersion{}, groups, project.Dependencies, "")
	requirements = addRequirements(requirements, groups, project.DependencyManagement.Dependencies, mavenutil.OriginManagement)

	// Requirements may not appear in the dependency graph but needs to be updated.
	for _, profile := range project.Profiles {
		reqsForUpdates = addRequirements(reqsForUpdates, groups, profile.Dependencies, "")
		reqsForUpdates = addRequirements(reqsForUpdates, groups, profile.DependencyManagement.Dependencies, mavenutil.OriginManagement)
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		reqsForUpdates = addRequirements(reqsForUpdates, groups, plugin.Dependencies, "")
	}

	return &mavenManifest{
		filePath: path,
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   project.ProjectKey.Name(),
				},
				VersionType: resolve.Concrete,
				Version:     string(project.Version),
			},
		},
		requirements: requirements,
		groups:       groups,
		specific: ManifestSpecific{
			Parent:                 project.Parent,
			Properties:             properties,
			OriginalRequirements:   origRequirements,
			RequirementsForUpdates: reqsForUpdates,
			Repositories:           project.Repositories,
		},
	}, nil
}

func addRequirements(reqs []resolve.RequirementVersion, groups map[manifest.RequirementKey][]string, deps []maven.Dependency, origin string) []resolve.RequirementVersion {
	for _, d := range deps {
		reqVer := makeRequirementVersion(d, origin)
		reqs = append(reqs, reqVer)
		if d.Scope != "" {
			reqKey := MakeRequirementKey(reqVer)
			groups[reqKey] = append(groups[reqKey], string(d.Scope))
		}
	}

	return reqs
}

func buildPropertiesWithOrigins(project maven.Project, originPrefix string) []PropertyWithOrigin {
	count := len(project.Properties.Properties)
	for _, prof := range project.Profiles {
		count += len(prof.Properties.Properties)
	}
	properties := make([]PropertyWithOrigin, 0, count)
	for _, prop := range project.Properties.Properties {
		properties = append(properties, PropertyWithOrigin{Property: prop})
	}
	for _, profile := range project.Profiles {
		for _, prop := range profile.Properties.Properties {
			properties = append(properties, PropertyWithOrigin{
				Property: prop,
				Origin:   mavenOrigin(originPrefix, mavenutil.OriginProfile, string(profile.ID)),
			})
		}
	}

	return properties
}

func buildOriginalRequirements(project maven.Project, originPrefix string) []DependencyWithOrigin {
	var dependencies []DependencyWithOrigin //nolint:prealloc
	if project.Parent.GroupID != "" && project.Parent.ArtifactID != "" {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: maven.Dependency{
				GroupID:    project.Parent.GroupID,
				ArtifactID: project.Parent.ArtifactID,
				Version:    project.Parent.Version,
				Type:       "pom",
			},
			Origin: mavenOrigin(originPrefix, mavenutil.OriginParent),
		})
	}
	for _, d := range project.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{Dependency: d, Origin: originPrefix})
	}
	for _, d := range project.DependencyManagement.Dependencies {
		dependencies = append(dependencies, DependencyWithOrigin{
			Dependency: d,
			Origin:     mavenOrigin(originPrefix, mavenutil.OriginManagement),
		})
	}
	for _, prof := range project.Profiles {
		for _, d := range prof.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginProfile, string(prof.ID)),
			})
		}
		for _, d := range prof.DependencyManagement.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginProfile, string(prof.ID), mavenutil.OriginManagement),
			})
		}
	}
	for _, plugin := range project.Build.PluginManagement.Plugins {
		for _, d := range plugin.Dependencies {
			dependencies = append(dependencies, DependencyWithOrigin{
				Dependency: d,
				Origin:     mavenOrigin(originPrefix, mavenutil.OriginPlugin, plugin.ProjectKey.Name()),
			})
		}
	}

	return dependencies
}

// For dependencies in profiles and plugins, we use origin to indicate where they are from.
// The origin is in the format prefix@identifier[@postfix] (where @ is the separator):
//   - prefix indicates it is from profile or plugin
//   - identifier to locate the profile/plugin which is profile ID or plugin name
//   - (optional) suffix indicates if this is a dependency management
func makeRequirementVersion(dep maven.Dependency, origin string) resolve.RequirementVersion {
	// Treat test & optional dependencies as regular dependencies to force the resolver to resolve them.
	if dep.Scope == "test" {
		dep.Scope = ""
	}
	dep.Optional = ""

	return resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.Maven,
				Name:   dep.Name(),
			},
			VersionType: resolve.Requirement,
			Version:     string(dep.Version),
		},
		Type: resolve.MavenDepType(dep, origin),
	}
}

func mavenOrigin(list ...string) string {
	result := ""
	for _, str := range list {
		if result != "" && str != "" {
			result += "@"
		}
		if str != "" {
			result += str
		}
	}

	return result
}
