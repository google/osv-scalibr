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

// Package pomxmlnet extracts Maven's pom.xml format with transitive dependency resolution.
package pomxmlnet

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/exp/maps"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	mavenresolve "deps.dev/util/resolve/maven"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor extracts Maven packages with transitive dependency resolution.
type Extractor struct {
	resolution.DependencyClient
	*datasource.MavenRegistryAPIClient
}

// Name of the extractor.
func (e Extractor) Name() string { return "java/pomxmlnet" }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network:  true,
		DirectFS: true,
	}
}

// FileRequired never returns true, as this is for the osv-scanner json output.
func (e Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filepath.Base(fapi.Path()) == "pom.xml"
}

// Extract extracts packages from yarn.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) ([]*extractor.Inventory, error) {
	var project maven.Project
	if err := datasource.NewMavenDecoder(input.Reader).Decode(&project); err != nil {
		return nil, fmt.Errorf("could not extract from %s: %w", input.Path, err)
	}
	// Empty JDK and ActivationOS indicates merging the default profiles.
	if err := project.MergeProfiles("", maven.ActivationOS{}); err != nil {
		return nil, fmt.Errorf("failed to merge profiles: %w", err)
	}
	for _, repo := range project.Repositories {
		if err := e.MavenRegistryAPIClient.AddRegistry(datasource.MavenRegistry{
			URL:              string(repo.URL),
			ID:               string(repo.ID),
			ReleasesEnabled:  repo.Releases.Enabled.Boolean(),
			SnapshotsEnabled: repo.Snapshots.Enabled.Boolean(),
		}); err != nil {
			return nil, fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
		}
	}
	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := mavenutil.MergeParents(ctx, input, e.MavenRegistryAPIClient, &project, project.Parent, 1, true); err != nil {
		return nil, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		return mavenutil.GetDependencyManagement(ctx, e.MavenRegistryAPIClient, groupID, artifactID, version)
	})

	if registries := e.MavenRegistryAPIClient.GetRegistries(); len(registries) > 0 {
		clientRegs := make([]resolution.Registry, len(registries))
		for i, reg := range registries {
			clientRegs[i] = reg
		}
		if err := e.DependencyClient.AddRegistries(clientRegs); err != nil {
			return nil, err
		}
	}

	overrideClient := resolution.NewOverrideClient(e.DependencyClient)
	resolver := mavenresolve.NewResolver(overrideClient)

	// Resolve the dependencies.
	root := resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.Maven,
				Name:   project.ProjectKey.Name(),
			},
			VersionType: resolve.Concrete,
			Version:     string(project.Version),
		}}
	reqs := make([]resolve.RequirementVersion, len(project.Dependencies)+len(project.DependencyManagement.Dependencies))
	for i, d := range project.Dependencies {
		reqs[i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   d.Name(),
				},
				VersionType: resolve.Requirement,
				Version:     string(d.Version),
			},
			Type: resolve.MavenDepType(d, ""),
		}
	}
	for i, d := range project.DependencyManagement.Dependencies {
		reqs[len(project.Dependencies)+i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   d.Name(),
				},
				VersionType: resolve.Requirement,
				Version:     string(d.Version),
			},
			Type: resolve.MavenDepType(d, mavenutil.OriginManagement),
		}
	}
	overrideClient.AddVersion(root, reqs)

	g, err := resolver.Resolve(ctx, root.VersionKey)
	if err != nil {
		return nil, fmt.Errorf("failed resolving %v: %w", root, err)
	}
	for i, e := range g.Edges {
		g.Edges[i] = e
	}

	details := map[string]*extractor.Inventory{}
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		depGroups := []string{}
		inventory := extractor.Inventory{
			Name:    node.Version.Name,
			Version: node.Version.Version,
			// TODO(#408): Add merged paths in here as well
			Locations: []string{input.Path},
		}
		// We are only able to know dependency groups of direct dependencies but
		// not transitive dependencies because the nodes in the resolve graph does
		// not have the scope information.
		for _, dep := range project.Dependencies {
			if dep.Name() != inventory.Name {
				continue
			}
			if dep.Scope != "" && dep.Scope != "compile" {
				depGroups = append(depGroups, string(dep.Scope))
			}
		}
		inventory.Metadata = osv.DepGroupMetadata{
			DepGroupVals: depGroups,
		}
		details[inventory.Name] = &inventory
	}

	return maps.Values(details), nil
}

// ToPURL converts an inventory created by this extractor into a PURL.
func (e Extractor) ToPURL(i *extractor.Inventory) *purl.PackageURL {
	g, a, _ := strings.Cut(i.Name, ":")
	return &purl.PackageURL{
		Type:      purl.TypeMaven,
		Namespace: g,
		Name:      a,
		Version:   i.Version,
		// TODO(#426): add Maven classifier and type to PURL.
	}
}

// Ecosystem returns the OSV ecosystem ('npm') of the software extracted by this extractor.
func (e Extractor) Ecosystem(_ *extractor.Inventory) string {
	return "Maven"
}

var _ filesystem.Extractor = Extractor{}
