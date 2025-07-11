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
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/internal/mavenutil"
	forkedxml "github.com/michaelkedar/xml"
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
	ParentPaths            []string                     // Paths to the parent pom.xml files
	Properties             []PropertyWithOrigin         // Properties from the base project and any local parent projects
	OriginalRequirements   []DependencyWithOrigin       // Dependencies from the base project
	LocalRequirements      []DependencyWithOrigin       // Dependencies from the base project and any local parent projects
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
			ParentPaths:            slices.Clone(m.specific.ParentPaths),
			Properties:             slices.Clone(m.specific.Properties),
			OriginalRequirements:   slices.Clone(m.specific.OriginalRequirements),
			LocalRequirements:      slices.Clone(m.specific.LocalRequirements),
			RequirementsForUpdates: slices.Clone(m.specific.RequirementsForUpdates),
			Repositories:           slices.Clone(m.specific.Repositories),
		},
	}
	clone.root.AttrSet = m.root.AttrSet.Clone()

	return clone
}

// PatchRequirement modifies the manifest's requirements to include the new requirement version.
// If the package already is in the requirements, updates the version.
// Otherwise, adds req to the dependencyManagement of the root pom.xml.
func (m *mavenManifest) PatchRequirement(req resolve.RequirementVersion) error {
	found := false
	i := 0
	for _, r := range m.requirements {
		if r.PackageKey != req.PackageKey {
			m.requirements[i] = r
			i++

			continue
		}
		origin, hasOrigin := r.Type.GetAttr(dep.MavenDependencyOrigin)
		if !hasOrigin || origin == mavenutil.OriginManagement {
			found = true
			r.Version = req.Version
			m.requirements[i] = r
			i++
		}
	}
	m.requirements = m.requirements[:i]
	if !found {
		req.Type.AddAttr(dep.MavenDependencyOrigin, mavenutil.OriginManagement)
		m.requirements = append(m.requirements, req)
	}

	return nil
}

type readWriter struct {
	*datasource.MavenRegistryAPIClient
}

// GetReadWriter returns a ReadWriter for pom.xml manifest files.
func GetReadWriter(remote, local string) (manifest.ReadWriter, error) {
	client, err := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: remote, ReleasesEnabled: true}, local)
	if err != nil {
		return nil, err
	}
	return readWriter{MavenRegistryAPIClient: client}, nil
}

// System returns the ecosystem of this ReadWriter.
func (r readWriter) System() resolve.System {
	return resolve.Maven
}

// SupportedStrategies returns the remediation strategies supported for this manifest.
func (r readWriter) SupportedStrategies() []strategy.Strategy {
	return []strategy.Strategy{strategy.StrategyOverride}
}

// Read parses the manifest from the given file.
func (r readWriter) Read(path string, fsys scalibrfs.FS) (manifest.Manifest, error) {
	// TODO(#472): much of this logic is duplicated with the pomxmlnet extractor.
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

	// TODO(#473): there may be properties in repo.Releases.Enabled and repo.Snapshots.Enabled
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
	if err := mavenutil.MergeParents(ctx, project.Parent, &project, mavenutil.Options{
		Input:              &filesystem.ScanInput{FS: fsys, Path: path},
		Client:             r.MavenRegistryAPIClient,
		AddRegistry:        true,
		AllowLocal:         true,
		InitialParentIndex: 1,
	}); err != nil {
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

	// Get the local dependencies and properties from all parent projects.
	localDeps, localProps, paths, err := getLocalDepsAndProps(fsys, path, project.Parent)
	if err != nil {
		return nil, err
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
			ParentPaths:            paths,
			Properties:             append(properties, localProps...),
			OriginalRequirements:   origRequirements,
			LocalRequirements:      append(origRequirements, localDeps...),
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

// TODO: refactor MergeParents to return local requirements and properties
func getLocalDepsAndProps(fsys scalibrfs.FS, path string, parent maven.Parent) ([]DependencyWithOrigin, []PropertyWithOrigin, []string, error) {
	var localDeps []DependencyWithOrigin
	var localProps []PropertyWithOrigin

	// Walk through local parent pom.xml for original dependencies and properties.
	currentPath := path
	visited := make(map[maven.ProjectKey]bool, mavenutil.MaxParent)
	paths := []string{currentPath}
	for range mavenutil.MaxParent {
		if parent.GroupID == "" || parent.ArtifactID == "" || parent.Version == "" {
			break
		}
		if visited[parent.ProjectKey] {
			// A cycle of parents is detected
			return nil, nil, nil, errors.New("a cycle of parents is detected")
		}
		visited[parent.ProjectKey] = true

		currentPath = mavenutil.ParentPOMPath(&filesystem.ScanInput{FS: fsys}, currentPath, string(parent.RelativePath))
		if currentPath == "" {
			// No more local parent pom.xml exists.
			break
		}

		f, err := fsys.Open(currentPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to open parent file %s: %w", currentPath, err)
		}

		var proj maven.Project
		err = datasource.NewMavenDecoder(f).Decode(&proj)
		f.Close()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to unmarshal project: %w", err)
		}
		if mavenutil.ProjectKey(proj) != parent.ProjectKey || proj.Packaging != "pom" {
			// This is not the project that we are looking for, we should fetch from upstream
			// that we don't have write access so we give up here.
			break
		}

		origin := mavenOrigin(mavenutil.OriginParent, currentPath)
		localDeps = append(localDeps, buildOriginalRequirements(proj, origin)...)
		localProps = append(localProps, buildPropertiesWithOrigins(proj, origin)...)
		paths = append(paths, currentPath)
		parent = proj.Parent
	}

	return localDeps, localProps, paths, nil
}

// Write writes the manifest after applying the patches to outputPath.
//
// original is the manifest without patches. fsys is the FS that the manifest was read from.
// outputPath is the path on disk (*not* in fsys) to write the entire patched manifest to (this can overwrite the original manifest).
//
// If the original manifest referenced local parent POMs, they will be written alongside the patched manifest, maintaining the relative path structure as it existed in the original location.
func (r readWriter) Write(original manifest.Manifest, fsys scalibrfs.FS, patches []result.Patch, outputPath string) error {
	specific, ok := original.EcosystemSpecific().(ManifestSpecific)
	if !ok {
		return errors.New("invalid maven ManifestSpecific data")
	}

	allPatches, err := buildPatches(patches, specific)
	if err != nil {
		return err
	}

	for _, patchPath := range specific.ParentPaths {
		patches := allPatches[patchPath]
		if patchPath == original.FilePath() {
			patches = allPatches[""]
		}
		depFile, err := fsys.Open(patchPath)
		if err != nil {
			return err
		}
		in := new(bytes.Buffer)
		if _, err := in.ReadFrom(depFile); err != nil {
			return fmt.Errorf("failed to read from filesystem: %w", err)
		}
		depFile.Close() // Make sure the file is closed before we start writing to it.

		out := new(bytes.Buffer)
		if err := write(in.String(), out, patches); err != nil {
			return err
		}
		// Write the patched parent relative to the new outputPath
		relativePatch, err := filepath.Rel(original.FilePath(), patchPath)
		if err != nil {
			return err
		}
		patchPath = filepath.Join(outputPath, relativePatch)
		if err := os.MkdirAll(filepath.Dir(patchPath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(patchPath, out.Bytes(), 0644); err != nil {
			return err
		}
	}

	return nil
}

// Patches represents all the dependencies and properties to be updated
type Patches struct {
	DependencyPatches DependencyPatches
	PropertyPatches   PropertyPatches
}

// Patch represents an individual dependency to be upgraded, and the version to upgrade to
type Patch struct {
	maven.DependencyKey

	NewRequire string
}

// DependencyPatches represent the dependencies to be updated, which
// is a map of dependency patches of each origin.
type DependencyPatches map[string]map[Patch]bool //  origin -> patch -> whether from this project

// addPatch adds a patch to the patches map indexed by origin.
// exist indicates whether this patch comes from the project.
func (m DependencyPatches) addPatch(changedDep result.PackageUpdate, exist bool) error {
	d, o, err := resolve.MavenDepTypeToDependency(changedDep.Type)
	if err != nil {
		return fmt.Errorf("MavenDepTypeToDependency: %w", err)
	}

	// If this dependency did not already exist in the project, we want to add it to the dependencyManagement section
	if !exist {
		o = mavenutil.OriginManagement
	}

	substrings := strings.Split(changedDep.Name, ":")
	if len(substrings) != 2 {
		return fmt.Errorf("invalid Maven name: %s", changedDep.Name)
	}
	d.GroupID = maven.String(substrings[0])
	d.ArtifactID = maven.String(substrings[1])

	if _, ok := m[o]; !ok {
		m[o] = make(map[Patch]bool)
	}
	m[o][Patch{
		DependencyKey: d.Key(),
		NewRequire:    changedDep.VersionTo,
	}] = exist

	return nil
}

// PropertyPatches represent the properties to be updated, which
// is a map of properties of each origin.
type PropertyPatches map[string]map[string]string // origin -> tag -> value

// parentPathFromOrigin returns the parent path embedded in origin,
// as well as the remaining origin string.
func parentPathFromOrigin(origin string) (string, string) {
	tokens := strings.Split(origin, "@")
	if len(tokens) <= 1 {
		return "", origin
	}
	if tokens[0] != mavenutil.OriginParent {
		return "", origin
	}

	return tokens[1], strings.Join(tokens[2:], "")
}

func iterUpgrades(patches []result.Patch) iter.Seq[result.PackageUpdate] {
	return func(yield func(result.PackageUpdate) bool) {
		for _, patch := range patches {
			for _, update := range patch.PackageUpdates {
				if !yield(update) {
					return
				}
			}
		}
	}
}

// buildPatches returns dependency patches ready for updates.
func buildPatches(patches []result.Patch, specific ManifestSpecific) (map[string]Patches, error) {
	result := make(map[string]Patches)
	for patch := range iterUpgrades(patches) {
		var path string
		origDep := OriginalDependency(patch, specific.LocalRequirements)
		path, origDep.Origin = parentPathFromOrigin(origDep.Origin)
		if _, ok := result[path]; !ok {
			result[path] = Patches{
				DependencyPatches: DependencyPatches{},
				PropertyPatches:   PropertyPatches{},
			}
		}
		if origDep.Name() == ":" {
			// An empty name indicates the dependency is not found, so the original dependency is not in the base project.
			// Add it so that it will be written into the dependencyManagement section.
			if err := result[path].DependencyPatches.addPatch(patch, false); err != nil {
				return nil, err
			}

			continue
		}

		patch.Type = resolve.MavenDepType(origDep.Dependency, origDep.Origin)
		if !origDep.Version.ContainsProperty() {
			// The original requirement does not contain a property placeholder.
			if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
				return nil, err
			}

			continue
		}

		properties, ok := generatePropertyPatches(string(origDep.Version), patch.VersionTo)
		if !ok {
			// Not able to update properties to update the requirement.
			// Update the dependency directly instead.
			if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
				return nil, err
			}

			continue
		}

		depOrigin := origDep.Origin
		if strings.HasPrefix(depOrigin, mavenutil.OriginProfile) {
			// Dependency management is not indicated in property origin.
			depOrigin, _ = strings.CutSuffix(depOrigin, "@"+mavenutil.OriginManagement)
		} else {
			// Properties are defined either universally or in a profile. For property
			// origin not starting with 'profile', this is an universal property.
			depOrigin = ""
		}

		for name, value := range properties {
			// A dependency in a profile may contain properties from this profile or
			// properties universally defined. We need to figure out the origin of these
			// properties. If a property is defined both universally and in the profile,
			// we use the profile's origin.
			propertyOrigin := ""
			for _, p := range specific.Properties {
				if p.Name == name && p.Origin != "" && p.Origin == depOrigin {
					propertyOrigin = depOrigin
				}
			}
			if _, ok := result[path].PropertyPatches[propertyOrigin]; !ok {
				result[path].PropertyPatches[propertyOrigin] = make(map[string]string)
			}
			// This property has been set to update to a value. If both values are the
			// same, we do nothing; otherwise, instead of updating the property, we
			// should update the dependency directly.
			if preset, ok := result[path].PropertyPatches[propertyOrigin][name]; !ok {
				result[path].PropertyPatches[propertyOrigin][name] = value
			} else if preset != value {
				if err := result[path].DependencyPatches.addPatch(patch, true); err != nil {
					return nil, err
				}
			}
		}
	}

	return result, nil
}

// OriginalDependency returns the original dependency of a dependency patch.
// If the dependency is not found in any local pom.xml, an empty dependency is returned.
func OriginalDependency(patch result.PackageUpdate, origDeps []DependencyWithOrigin) DependencyWithOrigin {
	IDs := strings.Split(patch.Name, ":")
	if len(IDs) != 2 {
		return DependencyWithOrigin{}
	}

	dependency, _, _ := resolve.MavenDepTypeToDependency(patch.Type)
	dependency.GroupID = maven.String(IDs[0])
	dependency.ArtifactID = maven.String(IDs[1])

	for _, d := range origDeps {
		if d.Key() == dependency.Key() && d.Version != "" {
			// If the version is empty, keep looking until we find some non-empty requirement.
			return d
		}
	}

	return DependencyWithOrigin{}
}

// generatePropertyPatches returns whether we are able to assign values to
// placeholder keys to convert s1 to s2, as well as the generated patches.
// s1 contains property placeholders like '${name}' and s2 is the target string.
func generatePropertyPatches(s1, s2 string) (map[string]string, bool) {
	patches := make(map[string]string)
	ok := generatePropertyPatchesAux(s1, s2, patches)

	return patches, ok
}

// generatePropertyPatchesAux generates property patches and store them in patches.
// TODO: property may refer to another property ${${name}.version}
func generatePropertyPatchesAux(s1, s2 string, patches map[string]string) bool {
	start := strings.Index(s1, "${")
	if s1[:start] != s2[:start] {
		// Cannot update property to match the prefix
		return false
	}
	end := strings.Index(s1, "}")
	next := strings.Index(s1[end+1:], "${")
	if next < 0 {
		// There are no more placeholders.
		remainder := s1[end+1:]
		if remainder == s2[len(s2)-len(remainder):] {
			patches[s1[start+2:end]] = s2[start : len(s2)-len(remainder)]
			return true
		}
	} else if match := strings.Index(s2[start:], s1[end+1:end+1+next]); match > 0 {
		// Try to match the substring between two property placeholders.
		patches[s1[start+2:end]] = s2[start : start+match]
		return generatePropertyPatchesAux(s1[end+1:], s2[start+match:], patches)
	}

	return false
}

func projectStartElement(raw string) string {
	start := strings.Index(raw, "<project")
	if start < 0 {
		return ""
	}
	end := strings.Index(raw[start:], ">")
	if end < 0 {
		return ""
	}

	return raw[start : start+end+1]
}

// Only for writing dependencies that are not from the base project.
type dependencyManagement struct {
	Dependencies []dependency `xml:"dependencies>dependency,omitempty"`
}

type dependency struct {
	GroupID    string `xml:"groupId,omitempty"`
	ArtifactID string `xml:"artifactId,omitempty"`
	Version    string `xml:"version,omitempty"`
	Type       string `xml:"type,omitempty"`
	Classifier string `xml:"classifier,omitempty"`
}

func makeDependency(patch Patch) dependency {
	d := dependency{
		GroupID:    string(patch.GroupID),
		ArtifactID: string(patch.ArtifactID),
		Version:    patch.NewRequire,
		Classifier: string(patch.Classifier),
	}
	if patch.Type != "" && patch.Type != "jar" {
		d.Type = string(patch.Type)
	}

	return d
}

func compareDependency(d1, d2 dependency) int {
	if i := cmp.Compare(d1.GroupID, d2.GroupID); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.ArtifactID, d2.ArtifactID); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.Type, d2.Type); i != 0 {
		return i
	}
	if i := cmp.Compare(d1.Classifier, d2.Classifier); i != 0 {
		return i
	}

	return cmp.Compare(d1.Version, d2.Version)
}

func write(raw string, w io.Writer, patches Patches) error {
	dec := forkedxml.NewDecoder(bytes.NewReader([]byte(raw)))
	enc := forkedxml.NewEncoder(w)

	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("getting token: %w", err)
		}

		if tt, ok := token.(forkedxml.StartElement); ok {
			if tt.Name.Local == "project" {
				type RawProject struct {
					InnerXML string `xml:",innerxml"`
				}
				var rawProj RawProject
				if err := dec.DecodeElement(&rawProj, &tt); err != nil {
					return err
				}

				// xml.EncodeToken writes a start element with its all name spaces.
				// It's very common to have a start project element with a few name spaces in Maven.
				// Thus this would cause a big diff when we try to encode the start element of project.

				// We first capture the raw start element string and write it.
				projectStart := projectStartElement(raw)
				if projectStart == "" {
					return errors.New("unable to get start element of project")
				}
				if _, err := w.Write([]byte(projectStart)); err != nil {
					return fmt.Errorf("writing start element of project: %w", err)
				}

				// Then we update the project by passing the innerXML and name spaces are not passed.
				updated := make(map[string]bool) // origin -> updated
				if err := writeProject(w, enc, rawProj.InnerXML, "", "", patches.DependencyPatches, patches.PropertyPatches, updated); err != nil {
					return fmt.Errorf("updating project: %w", err)
				}

				// Check whether dependency management is updated, if not, add a new section of dependency management.
				if dmPatches := patches.DependencyPatches[mavenutil.OriginManagement]; len(dmPatches) > 0 && !updated[mavenutil.OriginManagement] {
					enc.Indent("  ", "  ")
					var dm dependencyManagement
					for p := range dmPatches {
						dm.Dependencies = append(dm.Dependencies, makeDependency(p))
					}
					// Sort dependency management for consistency in testing.
					slices.SortFunc(dm.Dependencies, compareDependency)
					if err := enc.Encode(dm); err != nil {
						return err
					}
					if _, err := w.Write([]byte("\n\n")); err != nil {
						return err
					}
					enc.Indent("", "")
				}

				// Finally we write the end element of project.
				if _, err := w.Write([]byte("</project>")); err != nil {
					return fmt.Errorf("writing start element of project: %w", err)
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
		if err := enc.Flush(); err != nil {
			return err
		}
	}

	return nil
}

func writeProject(w io.Writer, enc *forkedxml.Encoder, raw, prefix, id string, patches DependencyPatches, properties PropertyPatches, updated map[string]bool) error {
	dec := forkedxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(forkedxml.StartElement); ok {
			switch tt.Name.Local {
			case "parent":
				updated["parent"] = true
				type RawParent struct {
					maven.ProjectKey

					InnerXML string `xml:",innerxml"`
				}
				var rawParent RawParent
				if err := dec.DecodeElement(&rawParent, &tt); err != nil {
					return err
				}
				req := string(rawParent.Version)
				if parentPatches, ok := patches["parent"]; ok {
					// There should only be one parent patch
					if len(parentPatches) > 1 {
						return fmt.Errorf("multiple parent patches: %v", parentPatches)
					}
					for k := range parentPatches {
						req = k.NewRequire
					}
				}
				if err := writeString(enc, "<parent>"+rawParent.InnerXML+"</parent>", map[string]string{"version": req}); err != nil {
					return fmt.Errorf("updating parent: %w", err)
				}

				continue
			case "properties":
				type RawProperties struct {
					InnerXML string `xml:",innerxml"`
				}
				var rawProperties RawProperties
				if err := dec.DecodeElement(&rawProperties, &tt); err != nil {
					return err
				}
				if err := writeString(enc, "<properties>"+rawProperties.InnerXML+"</properties>", properties[mavenOrigin(prefix, id)]); err != nil {
					return fmt.Errorf("updating properties: %w", err)
				}

				continue
			case "profile":
				if prefix != "" || id != "" {
					// Skip updating if prefix or id is set to avoid infinite recursion
					break
				}
				type RawProfile struct {
					maven.Profile

					InnerXML string `xml:",innerxml"`
				}
				var rawProfile RawProfile
				if err := dec.DecodeElement(&rawProfile, &tt); err != nil {
					return err
				}
				if err := writeProject(w, enc, "<profile>"+rawProfile.InnerXML+"</profile>", mavenutil.OriginProfile, string(rawProfile.ID), patches, properties, updated); err != nil {
					return fmt.Errorf("updating profile: %w", err)
				}

				continue
			case "plugin":
				if prefix != "" || id != "" {
					// Skip updating if prefix or id is set to avoid infinite recursion
					break
				}
				type RawPlugin struct {
					maven.Plugin

					InnerXML string `xml:",innerxml"`
				}
				var rawPlugin RawPlugin
				if err := dec.DecodeElement(&rawPlugin, &tt); err != nil {
					return err
				}
				if err := writeProject(w, enc, "<plugin>"+rawPlugin.InnerXML+"</plugin>", mavenutil.OriginPlugin, rawPlugin.ProjectKey.Name(), patches, properties, updated); err != nil {
					return fmt.Errorf("updating profile: %w", err)
				}

				continue
			case "dependencyManagement":
				type RawDependencyManagement struct {
					maven.DependencyManagement

					InnerXML string `xml:",innerxml"`
				}
				var rawDepMgmt RawDependencyManagement
				if err := dec.DecodeElement(&rawDepMgmt, &tt); err != nil {
					return err
				}
				o := mavenOrigin(prefix, id, mavenutil.OriginManagement)
				updated[o] = true
				dmPatches := patches[o]
				if err := writeDependency(w, enc, "<dependencyManagement>"+rawDepMgmt.InnerXML+"</dependencyManagement>", dmPatches); err != nil {
					return fmt.Errorf("updating dependency management: %w", err)
				}

				continue
			case "dependencies":
				type RawDependencies struct {
					Dependencies []maven.Dependency `xml:"dependencies"`
					InnerXML     string             `xml:",innerxml"`
				}
				var rawDeps RawDependencies
				if err := dec.DecodeElement(&rawDeps, &tt); err != nil {
					return err
				}
				o := mavenOrigin(prefix, id)
				updated[o] = true
				depPatches := patches[o]
				if err := writeDependency(w, enc, "<dependencies>"+rawDeps.InnerXML+"</dependencies>", depPatches); err != nil {
					return fmt.Errorf("updating dependencies: %w", err)
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}

// indentation returns the indentation of the dependency element.
// If dependencies or dependency elements are not found, the default
// indentation (four space) is returned.
func indentation(raw string) string {
	i := strings.Index(raw, "<dependencies>")
	if i < 0 {
		return "    "
	}

	raw = raw[i+len("<dependencies>"):]
	// Find the first dependency element.
	j := strings.Index(raw, "<dependency>")
	if j < 0 {
		return "    "
	}

	raw = raw[:j]
	// Find the last new line and get the space between.
	k := strings.LastIndex(raw, "\n")
	if k < 0 {
		return "    "
	}

	return raw[k+1:]
}

func writeDependency(w io.Writer, enc *forkedxml.Encoder, raw string, patches map[Patch]bool) error {
	dec := forkedxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}

		if tt, ok := token.(forkedxml.StartElement); ok {
			if tt.Name.Local == "dependencies" {
				// We still need to write the start element <dependencies>
				if err := enc.EncodeToken(token); err != nil {
					return err
				}
				if err := enc.Flush(); err != nil {
					return err
				}

				// Write patches that are not in the base project.
				var deps []dependency
				for p, ok := range patches {
					if !ok {
						deps = append(deps, makeDependency(p))
					}
				}
				if len(deps) == 0 {
					// No dependencies to add
					continue
				}
				// Sort dependencies for consistency in testing.
				slices.SortFunc(deps, compareDependency)

				enc.Indent(indentation(raw), "  ")
				// Write a new line to keep the format.
				if _, err := w.Write([]byte("\n")); err != nil {
					return err
				}
				for _, d := range deps {
					if err := enc.Encode(d); err != nil {
						return err
					}
				}
				enc.Indent("", "")

				continue
			}
			if tt.Name.Local == "dependency" {
				type RawDependency struct {
					maven.Dependency

					InnerXML string `xml:",innerxml"`
				}
				var rawDep RawDependency
				if err := dec.DecodeElement(&rawDep, &tt); err != nil {
					return err
				}
				req := string(rawDep.Version)
				for patch := range patches {
					// A Maven dependency key consists of Type and Classifier together with GroupID and ArtifactID.
					if patch.DependencyKey == rawDep.Key() {
						req = patch.NewRequire
					}
				}
				// xml.EncodeElement writes all empty elements and may not follow the existing format.
				// Passing the innerXML can help to keep the original format.
				if err := writeString(enc, "<dependency>"+rawDep.InnerXML+"</dependency>", map[string]string{"version": req}); err != nil {
					return fmt.Errorf("updating dependency: %w", err)
				}

				continue
			}
		}

		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}

// writeString writes XML string specified by raw with replacements specified in values.
func writeString(enc *forkedxml.Encoder, raw string, values map[string]string) error {
	dec := forkedxml.NewDecoder(bytes.NewReader([]byte(raw)))
	for {
		token, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if tt, ok := token.(forkedxml.StartElement); ok {
			if value, ok2 := values[tt.Name.Local]; ok2 {
				var str string
				if err := dec.DecodeElement(&str, &tt); err != nil {
					return err
				}
				if err := enc.EncodeElement(value, tt); err != nil {
					return err
				}

				continue
			}
		}
		if err := enc.EncodeToken(token); err != nil {
			return err
		}
	}

	return enc.Flush()
}
