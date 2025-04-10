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

package resolution

import (
	"context"
	"slices"
	"strings"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/clients/datasource"
)

// NPMRegistryClient is a client to fetch data from NPM registry.
type NPMRegistryClient struct {
	api *datasource.NPMRegistryAPIClient
}

// NewNPMRegistryClient makes a new NPMRegistryClient.
// projectDir is the directory (on disk) to read the project-level .npmrc config file from (for registries).
func NewNPMRegistryClient(projectDir string) (*NPMRegistryClient, error) {
	api, err := datasource.NewNPMRegistryAPIClient(projectDir)
	if err != nil {
		return nil, err
	}

	return &NPMRegistryClient{api: api}, nil
}

// Version returns metadata of a version specified by the VersionKey.
func (c *NPMRegistryClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	return resolve.Version{VersionKey: vk}, nil
}

// Versions returns all the available versions of the package specified by the given PackageKey.
func (c *NPMRegistryClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if isNPMBundle(pk) { // bundled dependencies
		return nil, nil
	}

	vers, err := c.api.Versions(ctx, pk.Name)
	if err != nil {
		return nil, err
	}

	vks := make([]resolve.Version, len(vers.Versions))
	for i, v := range vers.Versions {
		vks[i] = resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     v,
				VersionType: resolve.Concrete,
			}}
	}

	slices.SortFunc(vks, func(a, b resolve.Version) int { return semver.NPM.Compare(a.Version, b.Version) })

	return vks, nil
}

// Requirements returns requirements of a version specified by the VersionKey.
func (c *NPMRegistryClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if isNPMBundle(vk.PackageKey) { // bundled dependencies, return an empty set of requirements as a placeholder
		return []resolve.RequirementVersion{}, nil
	}
	dependencies, err := c.api.Dependencies(ctx, vk.Name, vk.Version)
	if err != nil {
		return nil, err
	}

	// Preallocate the dependency slice, which will hold all the dependencies of each type.
	// The npm resolver expects bundled dependencies included twice in different forms:
	// {foo@*|Scope="bundle"} and {mangled-name-of>0.1.2>foo@1.2.3}, hence the 2*len(bundled)
	depCount := len(dependencies.Dependencies) + len(dependencies.DevDependencies) +
		len(dependencies.OptionalDependencies) + len(dependencies.PeerDependencies) +
		2*len(dependencies.BundleDependencies)
	deps := make([]resolve.RequirementVersion, 0, depCount)
	addDeps := func(ds map[string]string, t dep.Type) {
		for name, req := range ds {
			typ := t.Clone()
			if r, ok := strings.CutPrefix(req, "npm:"); ok {
				// This dependency is aliased, add it as a
				// dependency on the actual name, with the
				// KnownAs attribute set to the alias.
				typ.AddAttr(dep.KnownAs, name)
				name = r
				req = ""
				if i := strings.LastIndex(r, "@"); i > 0 {
					name = r[:i]
					req = r[i+1:]
				}
			}
			deps = append(deps, resolve.RequirementVersion{
				Type: typ,
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.NPM,
						Name:   name,
					},
					VersionType: resolve.Requirement,
					Version:     req,
				},
			})
		}
	}
	addDeps(dependencies.Dependencies, dep.NewType())
	addDeps(dependencies.DevDependencies, dep.NewType(dep.Dev))
	addDeps(dependencies.OptionalDependencies, dep.NewType(dep.Opt))

	peerType := dep.NewType()
	peerType.AddAttr(dep.Scope, "peer")
	addDeps(dependencies.PeerDependencies, peerType)

	// TODO(#678): Support for bundled dependencies not implemented.
	// // The resolver expects bundleDependencies to be present as regular
	// // dependencies with a "*" version specifier, even if they were already
	// // in the regular dependencies.
	// bundleType := dep.NewType()
	// bundleType.AddAttr(dep.Scope, "bundle")
	// for _, name := range dependencies.BundleDependencies {
	// 	deps = append(deps, resolve.RequirementVersion{
	// 		Type: bundleType,
	// 		VersionKey: resolve.VersionKey{
	// 			PackageKey: resolve.PackageKey{
	// 				System: resolve.NPM,
	// 				Name:   name,
	// 			},
	// 			VersionType: resolve.Requirement,
	// 			Version:     "*",
	// 		},
	// 	})

	// 	// Correctly resolving the bundled dependencies would require downloading the package.
	// 	// Instead, just manually add a placeholder dependency with the mangled name.
	// 	mangledName := fmt.Sprintf("%s>%s>%s", vk.PackageKey.Name, vk.Version, name)
	// 	deps = append(deps, resolve.RequirementVersion{
	// 		Type: dep.NewType(),
	// 		VersionKey: resolve.VersionKey{
	// 			PackageKey: resolve.PackageKey{
	// 				System: resolve.NPM,
	// 				Name:   mangledName,
	// 			},
	// 			VersionType: resolve.Requirement,
	// 			Version:     "0.0.0",
	// 		},
	// 	})
	// }

	resolve.SortDependencies(deps)

	return deps, nil
}

// MatchingVersions returns versions matching the requirement specified by the VersionKey.
func (c *NPMRegistryClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if isNPMBundle(vk.PackageKey) { // bundled dependencies
		return nil, nil
	}

	versions, err := c.api.Versions(ctx, vk.Name)
	if err != nil {
		return nil, err
	}

	if concVer, ok := versions.Tags[vk.Version]; ok {
		// matched a tag, return just the concrete version of the tag
		return []resolve.Version{{
			VersionKey: resolve.VersionKey{
				PackageKey:  vk.PackageKey,
				Version:     concVer,
				VersionType: resolve.Concrete,
			},
		}}, nil
	}

	resVersions := make([]resolve.Version, len(versions.Versions))
	for i, v := range versions.Versions {
		resVersions[i] = resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  vk.PackageKey,
				Version:     v,
				VersionType: resolve.Concrete,
			},
		}
	}

	return resolve.MatchRequirement(vk, resVersions), nil
}

func isNPMBundle(pk resolve.PackageKey) bool {
	// Bundles are represented in resolution with a 'mangled' name containing its origin e.g. "root-pkg>1.0.0>bundled-package"
	// '>' is not a valid character for a npm package, so it'll only be found here.
	return strings.Contains(pk.Name, ">")
}
