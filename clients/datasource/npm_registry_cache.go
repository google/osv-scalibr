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
	"maps"
	"strings"
	"time"
)

type npmRegistryCache struct {
	Timestamp *time.Time                           // Timestamp of when this cache was made
	Details   map[string]npmRegistryPackageDetails // For a package name, the versions & their dependencies, and the list of tags
	ScopeURLs map[string]string                    // The URL of the registry used for a given package @scope. Used to invalidate cache if registry has changed.
}

// GobEncode encodes the cache to bytes.
func (c *NPMRegistryAPIClient) GobEncode() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cacheTimestamp == nil {
		now := time.Now().UTC()
		c.cacheTimestamp = &now
	}

	cache := npmRegistryCache{
		Timestamp: c.cacheTimestamp,
		Details:   c.details.GetMap(),
		ScopeURLs: make(map[string]string),
	}

	// store the registry URL for each scope (but not the auth info)
	cache.ScopeURLs = c.registries.ScopeURLs

	return gobMarshal(&cache)
}

// GobDecode decodes the cache from bytes.
func (c *NPMRegistryAPIClient) GobDecode(b []byte) error {
	// decode the cached data
	var cache npmRegistryCache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// remove any cache entries whose registry has changed
	maps.DeleteFunc(cache.Details, func(pkg string, _ npmRegistryPackageDetails) bool {
		scope := ""
		if strings.HasPrefix(pkg, "@") {
			scope, _, _ = strings.Cut(pkg, "/")
		}

		return cache.ScopeURLs[scope] != c.registries.ScopeURLs[scope]
	})

	c.cacheTimestamp = cache.Timestamp
	c.details.SetMap(cache.Details)

	return nil
}
