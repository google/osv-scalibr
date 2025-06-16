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

package datasource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/tidwall/gjson"
)

// NPMRegistryAPIClient defines a client to fetch metadata from a NPM registry.
type NPMRegistryAPIClient struct {
	// Registries from the npmrc config
	// This should only be written to when the client is first being created.
	// Other functions should not modify it & it is not covered by the mutex.
	registries NPMRegistryConfig

	// cache fields
	mu             sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	details        *RequestCache[string, npmRegistryPackageDetails]
}

// NewNPMRegistryAPIClient returns a new NPMRegistryAPIClient.
// projectDir is the directory (on disk) to read the project-level .npmrc config file from (for registries).
func NewNPMRegistryAPIClient(projectDir string) (*NPMRegistryAPIClient, error) {
	registryConfig, err := LoadNPMRegistryConfig(projectDir)
	if err != nil {
		return nil, err
	}
	return &NPMRegistryAPIClient{
		registries: registryConfig,
		details:    NewRequestCache[string, npmRegistryPackageDetails](),
	}, nil
}

// Versions returns all the known versions and tags of a given npm package
func (c *NPMRegistryAPIClient) Versions(ctx context.Context, pkg string) (NPMRegistryVersions, error) {
	pkgDetails, err := c.getPackageDetails(ctx, pkg)
	if err != nil {
		return NPMRegistryVersions{}, err
	}

	return NPMRegistryVersions{
		Versions: slices.AppendSeq(make([]string, 0, len(pkgDetails.Versions)), maps.Keys(pkgDetails.Versions)),
		Tags:     pkgDetails.Tags,
	}, nil
}

// Dependencies returns all the defined dependencies of the given version of an npm package
func (c *NPMRegistryAPIClient) Dependencies(ctx context.Context, pkg, version string) (NPMRegistryDependencies, error) {
	pkgDetails, err := c.getPackageDetails(ctx, pkg)
	if err != nil {
		return NPMRegistryDependencies{}, err
	}

	if deps, ok := pkgDetails.Versions[version]; ok {
		return deps, nil
	}

	return NPMRegistryDependencies{}, fmt.Errorf("no version %s for package %s", version, pkg)
}

// FullJSON returns the entire npm registry JSON data for a given package version
func (c *NPMRegistryAPIClient) FullJSON(ctx context.Context, pkg, version string) (gjson.Result, error) {
	return c.get(ctx, pkg, version)
}

func (c *NPMRegistryAPIClient) get(ctx context.Context, urlComponents ...string) (gjson.Result, error) {
	resp, err := c.registries.MakeRequest(ctx, http.DefaultClient, urlComponents...)
	if err != nil {
		return gjson.Result{}, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return gjson.Result{}, errors.New(resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return gjson.Result{}, err
	}

	res := gjson.ParseBytes(body)

	return res, nil
}

func (c *NPMRegistryAPIClient) getPackageDetails(ctx context.Context, pkg string) (npmRegistryPackageDetails, error) {
	return c.details.Get(pkg, func() (npmRegistryPackageDetails, error) {
		jsonData, err := c.get(ctx, pkg)
		if err != nil {
			return npmRegistryPackageDetails{}, err
		}

		versions := make(map[string]NPMRegistryDependencies)
		for v, data := range jsonData.Get("versions").Map() {
			versions[v] = NPMRegistryDependencies{
				Dependencies:         jsonToStringMap(data.Get("dependencies")),
				DevDependencies:      jsonToStringMap(data.Get("devDependencies")),
				PeerDependencies:     jsonToStringMap(data.Get("peerDependencies")),
				OptionalDependencies: jsonToStringMap(data.Get("optionalDependencies")),
				BundleDependencies:   jsonToStringSlice(data.Get("bundleDependencies")),
			}
		}

		return npmRegistryPackageDetails{
			Versions: versions,
			Tags:     jsonToStringMap(jsonData.Get("dist-tags")),
		}, nil
	})
}

func jsonToStringSlice(v gjson.Result) []string {
	arr := v.Array()
	if len(arr) == 0 {
		return nil
	}
	strs := make([]string, len(arr))
	for i, s := range arr {
		strs[i] = s.String()
	}

	return strs
}

func jsonToStringMap(v gjson.Result) map[string]string {
	mp := v.Map()
	if len(mp) == 0 {
		return nil
	}
	strs := make(map[string]string)
	for k, s := range mp {
		strs[k] = s.String()
	}

	return strs
}

type npmRegistryPackageDetails struct {
	// Only cache the info needed for the DependencyClient
	Versions map[string]NPMRegistryDependencies
	Tags     map[string]string
}

// NPMRegistryVersions holds the versions and tags of a package, from the npm API.
type NPMRegistryVersions struct {
	Versions []string
	Tags     map[string]string
}

// NPMRegistryDependencies holds the dependencies of a package version, from the npm API.
type NPMRegistryDependencies struct {
	Dependencies         map[string]string
	DevDependencies      map[string]string
	PeerDependencies     map[string]string
	OptionalDependencies map[string]string
	BundleDependencies   []string
}
