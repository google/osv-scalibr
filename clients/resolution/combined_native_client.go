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
	"fmt"
	"sync"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/datasource"
)

// CombinedNativeClient is a ResolutionClient that combines all the native clients:
// MavenRegistryClient, NPMRegistryClient, PyPIRegistryClient.
// Individual clients are lazy-initialized when needed.
type CombinedNativeClient struct {
	opts CombinedNativeClientOptions

	mu                  sync.Mutex
	mavenRegistryClient *MavenRegistryClient
	npmRegistryClient   *NPMRegistryClient
	pypiRegistryClient  *PyPIRegistryClient
}

// CombinedNativeClientOptions contains the options each client in the CombinedNativeClient.
type CombinedNativeClientOptions struct {
	ProjectDir        string                             // The project directory to use, currently only used for NPM to find .npmrc files.
	LocalRegistry     string                             // The local directory to store the downloaded manifests during resolution.
	MavenRegistry     string                             // The default Maven registry to use.
	PyPIRegistry      string                             // The default PyPI registry to use.
	MavenClient       *datasource.MavenRegistryAPIClient // The Maven registry client to use, if nil, a new client will be created.
	DisableGoogleAuth bool                               // If true, do not try to create google.DefaultClient for Artifact Registry.
}

// NewCombinedNativeClient makes a new CombinedNativeClient.
func NewCombinedNativeClient(opts CombinedNativeClientOptions) (*CombinedNativeClient, error) {
	client := &CombinedNativeClient{opts: opts}
	if opts.MavenClient != nil {
		client.mavenRegistryClient = NewMavenRegistryClientWithAPI(opts.MavenClient)
	}
	return client, nil
}

// Version returns metadata of a version specified by the VersionKey.
func (c *CombinedNativeClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	client, err := c.clientForSystem(ctx, vk.System)
	if err != nil {
		return resolve.Version{}, err
	}
	return client.Version(ctx, vk)
}

// Versions returns all the available versions of the package specified by the given PackageKey.
func (c *CombinedNativeClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	client, err := c.clientForSystem(ctx, pk.System)
	if err != nil {
		return nil, err
	}
	return client.Versions(ctx, pk)
}

// Requirements returns requirements of a version specified by the VersionKey.
func (c *CombinedNativeClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	client, err := c.clientForSystem(ctx, vk.System)
	if err != nil {
		return nil, err
	}
	return client.Requirements(ctx, vk)
}

// MatchingVersions returns versions matching the requirement specified by the VersionKey.
func (c *CombinedNativeClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	client, err := c.clientForSystem(ctx, vk.System)
	if err != nil {
		return nil, err
	}
	return client.MatchingVersions(ctx, vk)
}

// AddRegistries adds registries to the MavenRegistryClient.
func (c *CombinedNativeClient) AddRegistries(ctx context.Context, registries []Registry) error {
	// TODO(#541): Currently only MavenRegistryClient supports adding registries.
	// We might need to add support for PyPIRegistryClient.
	// But this AddRegistries method should take a system as input,
	// so that we can add registries to the corresponding client.
	client, err := c.clientForSystem(ctx, resolve.Maven)
	if err != nil {
		return err
	}
	regCl, ok := client.(ClientWithRegistries)
	if !ok {
		// Currently should not happen.
		return nil
	}
	return regCl.AddRegistries(ctx, registries)
}

func (c *CombinedNativeClient) clientForSystem(ctx context.Context, sys resolve.System) (resolve.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error
	switch sys {
	case resolve.Maven:
		if c.mavenRegistryClient == nil {
			c.mavenRegistryClient, err = NewMavenRegistryClient(ctx, c.opts.MavenRegistry, c.opts.LocalRegistry, c.opts.DisableGoogleAuth)
			if err != nil {
				return nil, err
			}
		}
		return c.mavenRegistryClient, nil
	case resolve.NPM:
		if c.npmRegistryClient == nil {
			c.npmRegistryClient, err = NewNPMRegistryClient(c.opts.ProjectDir)
			if err != nil {
				return nil, err
			}
		}
		return c.npmRegistryClient, nil
	case resolve.PyPI:
		if c.pypiRegistryClient == nil {
			c.pypiRegistryClient = NewPyPIRegistryClient(c.opts.PyPIRegistry, c.opts.LocalRegistry)
		}
		return c.pypiRegistryClient, nil
	case resolve.UnknownSystem:
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported system: %v", sys)
	}
}
