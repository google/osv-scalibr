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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/osv-scalibr/clients/datasource/internal/pypi"
)

// PyPIAPI holds the base of the URL of PyPI JSON API.
const PyPIAPI = "https://pypi.org/pypi/"

// PyPIRegistryAPIClient defines a client to fetch metadata from a PyPI registry.
type PyPIRegistryAPIClient struct {
	registry string

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	responses      *RequestCache[string, pypi.Response]
}

// NewPyPIRegistryAPIClient returns a new PyPIRegistryAPIClient.
func NewPyPIRegistryAPIClient(registry string) *PyPIRegistryAPIClient {
	return &PyPIRegistryAPIClient{
		registry:  registry,
		mu:        &sync.Mutex{},
		responses: NewRequestCache[string, pypi.Response](),
	}
}

func (p *PyPIRegistryAPIClient) GetPackageInfo(ctx context.Context, name string) (pypi.Response, error) {
	path, err := url.JoinPath(p.registry, name, "json")
	if err != nil {
		return pypi.Response{}, err
	}
	return p.get(ctx, path)
}

func (p *PyPIRegistryAPIClient) GetVersionInfo(ctx context.Context, name, version string) (pypi.Response, error) {
	path, err := url.JoinPath(p.registry, name, version, "json")
	if err != nil {
		return pypi.Response{}, err
	}
	return p.get(ctx, path)
}

func (p *PyPIRegistryAPIClient) get(ctx context.Context, url string) (pypi.Response, error) {
	return p.responses.Get(url, func() (pypi.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return pypi.Response{}, err
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return pypi.Response{}, fmt.Errorf("%w: PyPI registry query failed: %w", errAPIFailed, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return pypi.Response{}, errors.New(resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return pypi.Response{}, err
		}

		var result pypi.Response
		err = json.Unmarshal(body, &result)

		return result, err
	})
}
