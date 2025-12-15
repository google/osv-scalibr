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
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	mavenresolve "deps.dev/util/resolve/maven"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/internal/mavenutil"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "java/pomxmlnet"
)

// Extractor extracts Maven packages with transitive dependency resolution.
type Extractor struct {
	DepClient   resolve.Client
	MavenClient *datasource.MavenRegistryAPIClient
}

// New makes a new pom.xml transitive extractor with the given config.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	upstreamRegistry := ""
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.POMXMLNetConfig { return c.GetPomXmlNet() })
	if specific != nil {
		upstreamRegistry = specific.UpstreamRegistry
	}

	// No need to check errors since we are using the default Maven Central URL.
	mavenClient, _ := datasource.NewMavenRegistryAPIClient(context.Background(), datasource.MavenRegistry{
		URL:             upstreamRegistry,
		ReleasesEnabled: true,
	}, cfg.LocalRegistry, cfg.DisableGoogleAuth)
	depClient := resolution.NewMavenRegistryClientWithAPI(mavenClient)

	return &Extractor{
		DepClient:   depClient,
		MavenClient: mavenClient,
	}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		Network:  plugin.NetworkOnline,
		DirectFS: true,
	}
}

// FileRequired returns true if the specified file matches Maven POM lockfile patterns.
func (e Extractor) FileRequired(fapi filesystem.FileAPI) bool {
	return filepath.Base(fapi.Path()) == "pom.xml"
}

// Extract extracts packages from pom.xml files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var project maven.Project
	if err := datasource.NewMavenDecoder(input.Reader).Decode(&project); err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}
	// Empty JDK and ActivationOS indicates merging the default profiles.
	if err := project.MergeProfiles("", maven.ActivationOS{}); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to merge profiles: %w", err)
	}
	// Interpolate the repositories so that properties are resolved.
	if err := project.InterpolateRepositories(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to interpolate project: %w", err)
	}
	// Clear the registries that may be from other extraction.
	e.MavenClient = e.MavenClient.WithoutRegistries()
	for _, repo := range project.Repositories {
		if repo.URL.ContainsProperty() {
			continue
		}
		if err := e.MavenClient.AddRegistry(ctx, datasource.MavenRegistry{
			URL:              string(repo.URL),
			ID:               string(repo.ID),
			ReleasesEnabled:  repo.Releases.Enabled.Boolean(),
			SnapshotsEnabled: repo.Snapshots.Enabled.Boolean(),
		}); err != nil {
			return inventory.Inventory{}, fmt.Errorf("failed to add registry %s: %w", repo.URL, err)
		}
	}
	// Merging parents data by parsing local parent pom.xml or fetching from upstream.
	if err := mavenutil.MergeParents(ctx, project.Parent, &project, mavenutil.Options{
		Input:              input,
		Client:             e.MavenClient,
		AddRegistry:        true,
		AllowLocal:         true,
		InitialParentIndex: 1,
	}); err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to merge parents: %w", err)
	}
	// Process the dependencies:
	//  - dedupe dependencies and dependency management
	//  - import dependency management
	//  - fill in missing dependency version requirement
	project.ProcessDependencies(func(groupID, artifactID, version maven.String) (maven.DependencyManagement, error) {
		return mavenutil.GetDependencyManagement(ctx, e.MavenClient, groupID, artifactID, version)
	})

	if registries := e.MavenClient.GetRegistries(); len(registries) > 0 {
		clientRegs := make([]resolution.Registry, len(registries))
		for i, reg := range registries {
			clientRegs[i] = reg
		}
		if cl, ok := e.DepClient.(resolution.ClientWithRegistries); ok {
			if err := cl.AddRegistries(ctx, clientRegs); err != nil {
				return inventory.Inventory{}, err
			}
		}
	}

	overrideClient := resolution.NewOverrideClient(e.DepClient)
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
		return inventory.Inventory{}, fmt.Errorf("failed resolving %v: %w", root, err)
	}
	if len(g.Nodes) <= 1 && g.Error != "" {
		// Multi-registry error may be appended to the resolved graph so only return error when the graph is empty.
		return inventory.Inventory{}, fmt.Errorf("failed resolving %v: %s", root, g.Error)
	}

	details := map[string]*extractor.Package{}
	for i := 1; i < len(g.Nodes); i++ {
		// Ignore the first node which is the root.
		node := g.Nodes[i]
		depGroups := []string{}
		groupID, artifactID, _ := strings.Cut(node.Version.Name, ":")
		// We are only able to know dependency groups of direct dependencies but
		// not transitive dependencies because the nodes in the resolve graph does
		// not have the scope information.
		isDirect := false
		for _, dep := range project.Dependencies {
			if dep.Name() != node.Version.Name {
				continue
			}
			isDirect = true
			if dep.Scope != "" && dep.Scope != "compile" {
				depGroups = append(depGroups, string(dep.Scope))
			}
			break
		}
		pkg := extractor.Package{
			Name:     node.Version.Name,
			Version:  node.Version.Version,
			PURLType: purl.TypeMaven,
			Metadata: &javalockfile.Metadata{
				ArtifactID:   artifactID,
				GroupID:      groupID,
				DepGroupVals: depGroups,
				IsTransitive: !isDirect,
			},
			// TODO(#408): Add merged paths in here as well
			Locations: []string{input.Path},
		}
		details[pkg.Name] = &pkg
	}

	return inventory.Inventory{Packages: slices.Collect(maps.Values(details))}, nil
}

var _ filesystem.Extractor = Extractor{}
