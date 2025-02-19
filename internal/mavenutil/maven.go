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

// Package mavenutil provides utilities for merging Maven pom/xml.
package mavenutil

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/extractor/filesystem"
)

// Origin of the dependencies.
const (
	OriginManagement = "management"
	OriginParent     = "parent"
	OriginPlugin     = "plugin"
	OriginProfile    = "profile"
)

// MaxParent sets a limit on the number of parents to avoid indefinite loop.
const MaxParent = 100

// MergeParents parses local accessible parent pom.xml or fetches it from
// upstream, merges into root project, then interpolate the properties.
//   - result holds the Maven project to merge into, this is modified in place.
//   - current holds the current parent project to merge.
//   - parentIndex indicates the index of the current parent project, which is
//     used to check if the packaging has to be `pom`.
//   - allowLocal indicates whether parsing local parent pom.xml is allowed.
//   - path holds the path to the current pom.xml, which is used to compute the
//     relative path of parent.
func MergeParents(ctx context.Context, input *filesystem.ScanInput, mavenClient *datasource.MavenRegistryAPIClient, result *maven.Project, current maven.Parent, initialParentIndex int, allowLocal bool) error {
	currentPath := ""
	if input != nil {
		currentPath = input.Path
	}

	visited := make(map[maven.ProjectKey]struct{}, MaxParent)
	for n := initialParentIndex; n < MaxParent; n++ {
		if current.GroupID == "" || current.ArtifactID == "" || current.Version == "" {
			break
		}
		if _, ok := visited[current.ProjectKey]; ok {
			// A cycle of parents is detected
			return errors.New("a cycle of parents is detected")
		}
		visited[current.ProjectKey] = struct{}{}

		var proj maven.Project
		parentFoundLocally := false
		if allowLocal {
			var parentPath string
			var err error
			parentFoundLocally, parentPath, err = loadParentLocal(input, current, currentPath, &proj)
			if err != nil {
				return fmt.Errorf("failed to load parent at %s: %w", currentPath, err)
			}
			if parentPath != "" {
				currentPath = parentPath
			}
		}
		if !parentFoundLocally {
			// Once we fetch a parent pom.xml from upstream, we should not
			// allow parsing parent pom.xml locally anymore.
			allowLocal = false
			var err error
			proj, err = loadParentRemote(ctx, mavenClient, current, n)
			if err != nil {
				return fmt.Errorf("failed to load parent from remote: %w", err)
			}
		}
		// Use an empty JDK string and ActivationOS here to merge the default profiles.
		if err := result.MergeProfiles("", maven.ActivationOS{}); err != nil {
			return fmt.Errorf("failed to merge default profiles: %w", err)
		}
		for _, repo := range proj.Repositories {
			if err := mavenClient.AddRegistry(datasource.MavenRegistry{
				URL:              string(repo.URL),
				ID:               string(repo.ID),
				ReleasesEnabled:  repo.Releases.Enabled.Boolean(),
				SnapshotsEnabled: repo.Snapshots.Enabled.Boolean(),
			}); err != nil {
				return fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
			}
		}
		result.MergeParent(proj)
		current = proj.Parent
	}
	// Interpolate the project to resolve the properties.
	return result.Interpolate()
}

// loadParentLocal loads a parent Maven project from local file system
// and returns whether parent is found locally as well as parent path.
func loadParentLocal(input *filesystem.ScanInput, parent maven.Parent, path string, result *maven.Project) (bool, string, error) {
	parentPath := parentPOMPath(input, path, string(parent.RelativePath))
	if parentPath == "" {
		return false, "", nil
	}
	f, err := input.FS.Open(parentPath)
	if err != nil {
		return false, "", fmt.Errorf("failed to open parent file %s: %w", parentPath, err)
	}
	err = datasource.NewMavenDecoder(f).Decode(result)
	if closeErr := f.Close(); closeErr != nil {
		return false, "", fmt.Errorf("failed to close file: %w", err)
	}
	if err != nil {
		return false, "", fmt.Errorf("failed to unmarshal project: %w", err)
	}
	if ProjectKey(*result) != parent.ProjectKey || result.Packaging != "pom" {
		// Only mark parent as found when the identifiers and packaging are expected.
		return false, "", nil
	}
	return true, parentPath, nil
}

// loadParentRemote loads a parent from remote registry.
func loadParentRemote(ctx context.Context, mavenClient *datasource.MavenRegistryAPIClient, parent maven.Parent, parentIndex int) (maven.Project, error) {
	proj, err := mavenClient.GetProject(ctx, string(parent.GroupID), string(parent.ArtifactID), string(parent.Version))
	if err != nil {
		return maven.Project{}, fmt.Errorf("failed to get Maven project %s:%s:%s: %w", parent.GroupID, parent.ArtifactID, parent.Version, err)
	}
	if parentIndex > 0 && proj.Packaging != "pom" {
		// A parent project should only be of "pom" packaging type.
		return maven.Project{}, fmt.Errorf("invalid packaging for parent project %s", proj.Packaging)
	}
	if ProjectKey(proj) != parent.ProjectKey {
		// The identifiers in parent does not match what we want.
		return maven.Project{}, fmt.Errorf("parent identifiers mismatch: %v, expect %v", proj.ProjectKey, parent.ProjectKey)
	}
	return proj, nil
}

// ProjectKey returns a project key with empty groupId/version
// filled by corresponding fields in parent.
func ProjectKey(proj maven.Project) maven.ProjectKey {
	if proj.GroupID == "" {
		proj.GroupID = proj.Parent.GroupID
	}
	if proj.Version == "" {
		proj.Version = proj.Parent.Version
	}

	return proj.ProjectKey
}

// parentPOMPath returns the path of a parent pom.xml.
// Maven looks for the parent POM first in 'relativePath', then
// the local repository '../pom.xml', and lastly in the remote repo.
// An empty string is returned if failed to resolve the parent path.
func parentPOMPath(input *filesystem.ScanInput, currentPath, relativePath string) string {
	if relativePath == "" {
		relativePath = "../pom.xml"
	}

	path := filepath.ToSlash(filepath.Join(filepath.Dir(currentPath), relativePath))
	if info, err := input.FS.Stat(path); err == nil {
		if !info.IsDir() {
			return path
		}
		// Current path is a directory, so look for pom.xml in the directory.
		path = filepath.ToSlash(filepath.Join(path, "pom.xml"))
		if _, err := input.FS.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// GetDependencyManagement returns managed dependencies in the specified Maven project by fetching remote pom.xml.
func GetDependencyManagement(ctx context.Context, client *datasource.MavenRegistryAPIClient, groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
	root := maven.Parent{ProjectKey: maven.ProjectKey{GroupID: groupID, ArtifactID: artifactID, Version: version}}
	var result maven.Project
	// To get dependency management from another project, we need the
	// project with parents merged, so we call MergeParents by passing
	// an empty project.
	if err := MergeParents(ctx, nil, client.WithoutRegistries(), &result, root, 0, false); err != nil {
		return maven.DependencyManagement{}, err
	}

	return result.DependencyManagement, nil
}
