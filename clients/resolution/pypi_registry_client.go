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

	"deps.dev/util/pypi"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/version"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/clients/datasource"
)

// PyPIRegistryClient is a client to fetch data from PyPI registry.
type PyPIRegistryClient struct {
	api *datasource.PyPIRegistryAPIClient
}

// NewPyPIRegistryClient makes a new PyPIRegistryClient.
func NewPyPIRegistryClient(registry string) *PyPIRegistryClient {
	return &PyPIRegistryClient{api: datasource.NewPyPIRegistryAPIClient(registry)}
}

// Version returns metadata of a version specified by the VersionKey.
func (c *PyPIRegistryClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	// Version is not used by the PyPI resolver for now, so here
	// only returns the VersionKey with yanked or not.
	// We may need to add more metadata in the future.
	resp, err := c.api.GetVersionJson(ctx, vk.Name, vk.Version)
	if err != nil {
		return resolve.Version{}, err
	}
	ver := resolve.Version{VersionKey: vk}
	if resp.Info.Yanked {
		var yanked version.AttrSet
		yanked.SetAttr(version.Blocked, "")
		ver.AttrSet = yanked
	}
	return ver, nil
}

// Versions returns all the available versions of the package specified by the given PackageKey.
func (c *PyPIRegistryClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	vers, err := c.api.GetVersions(ctx, pk.Name)
	if err != nil {
		return nil, err
	}

	slices.SortFunc(vers, func(a, b string) int { return semver.PyPI.Compare(a, b) })

	var yanked version.AttrSet
	yanked.SetAttr(version.Blocked, "")

	var versions []resolve.Version
	for _, ver := range vers {
		v := resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				Version:     ver,
				VersionType: resolve.Concrete,
			},
		}

		resp, err := c.api.GetVersionJson(ctx, pk.Name, ver)
		if err != nil {
			return nil, err
		}
		if resp.Info.Yanked {
			v.AttrSet = yanked
		}
		versions = append(versions, v)
	}

	return versions, nil
}

// Requirements returns requirements of a version specified by the VersionKey.
func (c *PyPIRegistryClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	resp, err := c.api.GetVersionJson(ctx, vk.Name, vk.Version)
	if err != nil {
		return nil, err
	}

	var reqs []resolve.RequirementVersion
	for _, dist := range resp.Info.RequiresDist {
		d, err := pypi.ParseDependency(dist)
		if err != nil {
			return nil, err
		}

		t := dep.NewType()
		if d.Extras != "" {
			t.AddAttr(dep.EnabledDependencies, d.Extras)
		}
		if d.Environment != "" {
			t.AddAttr(dep.Environment, d.Environment)
		}

		reqs = append(reqs, resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.PyPI,
					Name:   d.Name,
				},
				Version:     d.Constraint,
				VersionType: resolve.Requirement,
			},
			Type: t,
		})
	}

	return reqs, nil
}

// MatchingVersions returns versions matching the requirement specified by the VersionKey.
func (c *PyPIRegistryClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	versions, err := c.Versions(ctx, vk.PackageKey)
	if err != nil {
		return nil, err
	}

	return resolve.MatchRequirement(vk, versions), nil
}
