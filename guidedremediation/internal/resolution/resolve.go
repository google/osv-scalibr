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

// Package resolution provides dependency graph resolution and vulnerability findings
// for guided remediation.
package resolution

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	mavenresolve "deps.dev/util/resolve/maven"
	npmresolve "deps.dev/util/resolve/npm"
	client "github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/internal/mavenutil"
)

// Resolve resolves the dependencies in the manifest using the provided client.
func Resolve(ctx context.Context, c resolve.Client, m manifest.Manifest, opts options.ResolutionOptions) (*resolve.Graph, error) {
	// Insert the manifest dependency into the client
	cl := client.NewOverrideClient(c)
	cl.AddVersion(m.Root(), m.Requirements())
	for _, lm := range m.LocalManifests() {
		cl.AddVersion(lm.Root(), lm.Requirements())
	}

	var r resolve.Resolver
	var sys = m.System()
	switch sys {
	case resolve.NPM:
		r = npmresolve.NewResolver(cl)
	case resolve.Maven:
		r = mavenresolve.NewResolver(cl)
	default:
		return nil, fmt.Errorf("no resolver for ecosystem %v", sys)
	}

	graph, err := r.Resolve(ctx, m.Root().VersionKey)
	if err != nil {
		return nil, fmt.Errorf("error resolving manifest dependencies: %w", err)
	}

	if graph.Error != "" {
		return nil, fmt.Errorf("manifest resolved with error: %s", graph.Error)
	}

	return resolvePostProcess(ctx, cl, m, opts, graph)
}

func resolvePostProcess(ctx context.Context, cl resolve.Client, m manifest.Manifest, opts options.ResolutionOptions, graph *resolve.Graph) (*resolve.Graph, error) {
	if m.System() == resolve.Maven && opts.MavenManagement {
		// Add a node & edge for each dependency in dependencyManagement that doesn't already appear in the resolved graph
		manifestSpecific, ok := m.EcosystemSpecific().(maven.ManifestSpecific)
		if !ok {
			return graph, errors.New("invalid maven ManifestSpecific data")
		}

		// Search through OriginalRequirements management dependencies in this pom only (not parents).
		for _, req := range manifestSpecific.OriginalRequirements {
			if req.Origin != mavenutil.OriginManagement {
				// TODO(#463): also check management in activated profiles and dependencies in inactive profiles.
				continue
			}

			// Unique identifier for this package.
			reqKey := MakeRequirementKey(resolve.RequirementVersion{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   req.Name(),
					},
					VersionType: resolve.Requirement,
					Version:     string(req.Version),
				},
				Type: resolve.MavenDepType(req.Dependency, req.Origin),
			})

			// Find the current version of the dependencyManagement dependency, after property interpolation & changes from remediation.
			requirements := m.Requirements()
			idx := slices.IndexFunc(requirements, func(rv resolve.RequirementVersion) bool {
				if origin, _ := rv.Type.GetAttr(dep.MavenDependencyOrigin); origin != mavenutil.OriginManagement {
					return false
				}

				return reqKey == MakeRequirementKey(rv)
			})

			if idx == -1 {
				// Ideally, this would be an error, but there a few known instances where this lookup fails:
				// 1. The artifact name contain a property (properties aren't substituted in OriginalRequirements, but are in Manifest.Requirements)
				// 2. Missing properties (due to e.g. un-activated profiles) cause the dependency to be invalid, and therefore excluded from Manifest.Requirements.
				// Ignore these dependencies in these cases so that we can still remediation vulns in the other packages.
				continue
			}

			rv := requirements[idx]

			// See if the package is already in the resolved graph.
			// Check the edges so we can make sure the ArtifactTypes and Classifiers match.
			if !slices.ContainsFunc(graph.Edges, func(e resolve.Edge) bool {
				return reqKey == MakeRequirementKey(resolve.RequirementVersion{
					VersionKey: graph.Nodes[e.To].Version,
					Type:       e.Type,
				})
			}) {
				// Management dependency not in graph - create the node.
				// Find the version the management requirement would resolve to.
				// First assume it's a soft requirement.
				vk := rv.VersionKey
				vk.VersionType = resolve.Concrete
				if _, err := cl.Version(ctx, vk); err != nil {
					// Not a soft requirement - try find a match.
					vk.VersionType = resolve.Requirement
					vks, err := cl.MatchingVersions(ctx, vk)
					if err != nil || len(vks) == 0 {
						err = graph.AddError(0, vk, fmt.Sprintf("could not find a version that satisfies requirement %s for package %s", vk.Version, vk.Name))
						if err != nil {
							return nil, err
						}

						continue
					}
					vk = vks[len(vks)-1].VersionKey
				}
				// Add the node & and edge from the root.
				nID := graph.AddNode(vk)
				if err := graph.AddEdge(0, nID, rv.Version, rv.Type.Clone()); err != nil {
					return nil, err
				}
			}
		}
	}

	return graph, nil
}
