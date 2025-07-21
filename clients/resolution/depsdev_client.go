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
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/datasource"
)

// DepsDevClient is a ResolutionClient wrapping the official resolve.APIClient
type DepsDevClient struct {
	resolve.APIClient

	c *datasource.CachedInsightsClient
}

// NewDepsDevClient creates a new DepsDevClient.
func NewDepsDevClient(addr string, userAgent string) (*DepsDevClient, error) {
	c, err := datasource.NewCachedInsightsClient(addr, userAgent)
	if err != nil {
		return nil, err
	}

	return &DepsDevClient{APIClient: *resolve.NewAPIClient(c), c: c}, nil
}
