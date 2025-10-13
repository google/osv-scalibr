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
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/clients/internal/pypi"
	"github.com/google/osv-scalibr/log"
)

// pyPIAPI holds the base of the URL of PyPI Index API.
const pyPIAPI = "https://pypi.org/simple"

// PyPIRegistryAPIClient defines a client to fetch metadata from a PyPI registry.
// TODO(#541): support multiple registries and authentication
type PyPIRegistryAPIClient struct {
	registry      string
	localRegistry string

	// Cache fields
	mu             *sync.Mutex
	cacheTimestamp *time.Time // If set, this means we loaded from a cache
	responses      *RequestCache[string, response]
}

// NewPyPIRegistryAPIClient returns a new PyPIRegistryAPIClient.
func NewPyPIRegistryAPIClient(registry string, localRegistry string) *PyPIRegistryAPIClient {
	if registry == "" {
		registry = pyPIAPI
	}
	if localRegistry != "" {
		localRegistry = filepath.Join(localRegistry, "pypi")
	}
	return &PyPIRegistryAPIClient{
		registry:      registry,
		localRegistry: localRegistry,
		mu:            &sync.Mutex{},
		responses:     NewRequestCache[string, response](),
	}
}

// SetLocalRegistry sets the local directory that stores the downloaded PyPI manifests.
func (p *PyPIRegistryAPIClient) SetLocalRegistry(localRegistry string) {
	if localRegistry != "" {
		localRegistry = filepath.Join(localRegistry, "pypi")
	}
	p.localRegistry = localRegistry
}

// GetIndex queries the simple API index for a given project.
func (p *PyPIRegistryAPIClient) GetIndex(ctx context.Context, project string) (pypi.IndexResponse, error) {
	reqPath, err := url.JoinPath(p.registry, project)
	if err != nil {
		return pypi.IndexResponse{}, err
	}

	// The Index API requires an ending slash.
	if !strings.HasSuffix(reqPath, "/") {
		reqPath += "/"
	}

	var indexResp pypi.IndexResponse
	resp, err := p.get(ctx, reqPath, true)
	if err != nil {
		return pypi.IndexResponse{}, err
	}
	err = json.Unmarshal(resp, &indexResp)
	return indexResp, err
}

// GetFile retrieves the content of a file from the registry at the given URL.
func (p *PyPIRegistryAPIClient) GetFile(ctx context.Context, url string) ([]byte, error) {
	return p.get(ctx, url, false)
}

// urlToPath converts a URL to a file path.
func urlToPath(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Warnf("Error parsing URL %s: %s", rawURL, err)
		return ""
	}
	return path.Join(parsedURL.Hostname(), parsedURL.Path)
}

func (p *PyPIRegistryAPIClient) get(ctx context.Context, url string, queryIndex bool) ([]byte, error) {
	file := ""
	urlPath := urlToPath(url)
	if urlPath != "" && p.localRegistry != "" {
		file = filepath.Join(p.localRegistry, urlPath)
		if content, err := os.ReadFile(file); err == nil {
			// We can still fetch the file from upstream if error is not nil.
			return content, nil
		}
	}

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

		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return response{}, fmt.Errorf("failed to read body: %w", err)
		}

		if file != "" {
			if err := writeFile(file, b); err != nil {
				log.Warnf("failed to write response of %s: %v", url, err)
			}
		}

		return response{StatusCode: resp.StatusCode, Body: b}, nil
	})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: PyPI registry query status: %d", errAPIFailed, resp.StatusCode)
	}

	return resp.Body, nil
}
