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

//nolint:dupl
package datasource

import (
	"time"
)

type pypiRegistryCache struct {
	Timestamp *time.Time
	Responses map[string]response // url -> response
}

// GobEncode encodes cache to bytes.
func (p *PyPIRegistryAPIClient) GobEncode() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cacheTimestamp == nil {
		now := time.Now().UTC()
		p.cacheTimestamp = &now
	}

	cache := pypiRegistryCache{
		Timestamp: p.cacheTimestamp,
		Responses: p.responses.GetMap(),
	}

	return gobMarshal(&cache)
}

// GobDecode encodes bytes to cache.
func (p *PyPIRegistryAPIClient) GobDecode(b []byte) error {
	var cache pypiRegistryCache
	if err := gobUnmarshal(b, &cache); err != nil {
		return err
	}

	if cache.Timestamp != nil && time.Since(*cache.Timestamp) >= cacheExpiry {
		// Cache expired
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	p.cacheTimestamp = cache.Timestamp
	p.responses.SetMap(cache.Responses)

	return nil
}
