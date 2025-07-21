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

	"deps.dev/util/resolve"
)

// OverrideClient wraps a resolve.Client, allowing for custom packages & versions to be added
type OverrideClient struct {
	resolve.Client

	// Can't quite reuse resolve.LocalClient because it automatically creates dependencies
	pkgVers map[resolve.PackageKey][]resolve.Version            // versions of a package
	verDeps map[resolve.VersionKey][]resolve.RequirementVersion // dependencies of a version
}

// NewOverrideClient makes a new OverrideClient.
func NewOverrideClient(c resolve.Client) *OverrideClient {
	return &OverrideClient{
		Client:  c,
		pkgVers: make(map[resolve.PackageKey][]resolve.Version),
		verDeps: make(map[resolve.VersionKey][]resolve.RequirementVersion),
	}
}

// AddVersion adds the specified version and dependencies to the client.
func (c *OverrideClient) AddVersion(v resolve.Version, deps []resolve.RequirementVersion) {
	// TODO: Inserting multiple co-dependent requirements may not work, depending on order
	versions := c.pkgVers[v.PackageKey]
	sem := v.Semver()
	// Only add it to the versions if not already there (and keep versions sorted)
	idx, ok := slices.BinarySearchFunc(versions, v, func(a, b resolve.Version) int {
		return sem.Compare(a.Version, b.Version)
	})
	if !ok {
		versions = slices.Insert(versions, idx, v)
	}
	c.pkgVers[v.PackageKey] = versions
	c.verDeps[v.VersionKey] = slices.Clone(deps) // overwrites dependencies if called multiple times with same version
}

// Version returns the version specified by the VersionKey.
func (c *OverrideClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	for _, v := range c.pkgVers[vk.PackageKey] {
		if v.VersionKey == vk {
			return v, nil
		}
	}

	return c.Client.Version(ctx, vk)
}

// Versions returns the versions of a package specified by the PackageKey.
func (c *OverrideClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if vers, ok := c.pkgVers[pk]; ok {
		return vers, nil
	}

	return c.Client.Versions(ctx, pk)
}

// Requirements returns the requirement versions of the version specified by the VersionKey.
func (c *OverrideClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if deps, ok := c.verDeps[vk]; ok {
		return deps, nil
	}

	return c.Client.Requirements(ctx, vk)
}

// MatchingVersions returns the versions matching the requirement specified by the VersionKey.
func (c *OverrideClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if vs, ok := c.pkgVers[vk.PackageKey]; ok {
		return resolve.MatchRequirement(vk, vs), nil
	}

	return c.Client.MatchingVersions(ctx, vk)
}
