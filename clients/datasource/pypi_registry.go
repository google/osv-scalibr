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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/clients/datasource/internal/pypi"
)

// PyPIAPI holds the base of the URL of PyPI JSON and Index API.
const PyPIAPI = "https://pypi.org/"

// PyPIRegistryAPIClient defines a client to fetch metadata from a PyPI registry.
// TODO(#541): support multiple registries and authentication
type PyPIRegistryAPIClient struct {
	registry string

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	responses      *RequestCache[string, response]
}

// NewPyPIRegistryAPIClient returns a new PyPIRegistryAPIClient.
func NewPyPIRegistryAPIClient(registry string) *PyPIRegistryAPIClient {
	return &PyPIRegistryAPIClient{
		registry:  registry,
		mu:        &sync.Mutex{},
		responses: NewRequestCache[string, response](),
	}
}

// GetRequiresDist queries the JSON API and returns the requires dist for a specific version.
func (p *PyPIRegistryAPIClient) GetVersionJson(ctx context.Context, project, version string) (pypi.JsonResponse, error) {
	path, err := url.JoinPath(p.registry, "pypi", project, version, "json")
	if err != nil {
		return pypi.JsonResponse{}, err
	}

	var jsonResp pypi.JsonResponse
	err = p.get(ctx, path, false, &jsonResp)
	return jsonResp, err
}

// GetVersions queries the Index API and returns the list of versions.
func (p *PyPIRegistryAPIClient) GetVersions(ctx context.Context, project string) ([]string, error) {
	resp, err := p.getIndex(ctx, project)
	if err != nil {
		return nil, err
	}
	return resp.Versions, nil
}

func (p *PyPIRegistryAPIClient) getIndex(ctx context.Context, project string) (pypi.IndexReponse, error) {
	path, err := url.JoinPath(p.registry, "simple", project)
	if err != nil {
		return pypi.IndexReponse{}, err
	}

	// The Index API requires an ending slash.
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	var indexResp pypi.IndexReponse
	err = p.get(ctx, path, true, &indexResp)
	return indexResp, err
}

func (p *PyPIRegistryAPIClient) get(ctx context.Context, url string, queryIndex bool, dst interface{}) error {
	resp, err := p.responses.Get(url, func() (response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return response{}, err
		}

		if queryIndex {
			req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return response{}, fmt.Errorf("%w: PyPI registry query failed: %w", errAPIFailed, err)
		}
		defer resp.Body.Close()

		if !slices.Contains([]int{http.StatusOK, http.StatusNotFound, http.StatusUnauthorized}, resp.StatusCode) {
			// Only cache responses with Status OK, NotFound, or Unauthorized
			return response{}, fmt.Errorf("%w: PyPI registry query status: %d", errAPIFailed, resp.StatusCode)
		}

		if b, err := io.ReadAll(resp.Body); err == nil {
			return response{StatusCode: resp.StatusCode, Body: b}, nil
		}

		return response{}, fmt.Errorf("failed to read body: %w", err)
	})
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: PyPI registry query status: %d", errAPIFailed, resp.StatusCode)
	}

	return json.Unmarshal(resp.Body, dst)
}
