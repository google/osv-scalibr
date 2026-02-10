// Copyright 2026 Google LLC
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

// Package herokuexpiration contains an Enricher that augments Heroku Platform Keys
// with expiration metadata from the key-query endpoint.
package herokuexpiration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/herokuplatformkey"
)

const (
	// Name is the unique name of this Enricher.
	Name = "secrets/herokuexpiration"

	version        = 1
	defaultBaseURL = "https://api.heroku.com"
)

var _ enricher.Enricher = &Enricher{}

// Enricher augments Heroku Platform Keys with expiration metadata.
type Enricher struct {
	baseURL    string
	httpClient *http.Client
}

// New creates a new Enricher with default configuration.
func New() enricher.Enricher {
	return &Enricher{
		baseURL:    defaultBaseURL,
		httpClient: http.DefaultClient,
	}
}

// NewWithBaseURL creates a new Enricher using a custom base URL (for tests).
func NewWithBaseURL(baseURL string) enricher.Enricher {
	return &Enricher{
		baseURL:    baseURL,
		httpClient: http.DefaultClient,
	}
}

// Name of the Enricher.
func (Enricher) Name() string { return Name }

// Version of the Enricher.
func (Enricher) Version() int { return version }

// Requirements of the Enricher (needs network access).
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{Network: plugin.NetworkOnline}
}

// RequiredPlugins returns the plugins that are required to be enabled for this Enricher to run.
func (Enricher) RequiredPlugins() []string { return []string{} }

// Enrich augments Heroku Platform Keys with expiration metadata obtained from the API.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	for _, s := range inv.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		tok, ok := s.Secret.(herokuplatformkey.HerokuSecret)
		if !ok || tok.Key == "" {
			continue
		}

		expireTime, neverExpires, err := e.fetchExpiration(ctx, tok.Key)
		if err != nil {
			continue
		}
		tok.ExpireTime = expireTime
		tok.NeverExpires = neverExpires
		s.Secret = tok
	}
	return nil
}

// authorizationResponse and accessTokenResponse represents the Heroku Platform endpoint response.
// Only some of the fields are included for enrichment.
// See https://devcenter.heroku.com/articles/platform-api-reference#oauth-authorization
type authorizationResponse struct {
	AccessToken accessTokenResponse `json:"access_token"`
}

type accessTokenResponse struct {
	ExpiresIn *int   `json:"expires_in"` // nil when null
	Token     string `json:"token"`
}

func (e *Enricher) fetchExpiration(ctx context.Context, bearer string) (time.Duration, bool, error) {
	url := e.baseURL + "/oauth/authorizations"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Duration(0), false, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")
	res, err := e.httpClient.Do(req)
	if err != nil {
		return time.Duration(0), false, fmt.Errorf("http GET: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// Treat non-200 as non-fatal; skip enrichment.
		_, _ = io.Copy(io.Discard, res.Body)
		return time.Duration(0), false, nil
	}
	var raw []authorizationResponse

	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return time.Duration(0), false, fmt.Errorf("decode response: %w", err)
	}
	for _, a := range raw {
		if a.AccessToken.Token == bearer {
			if a.AccessToken.ExpiresIn == nil {
				return time.Duration(0), true, nil
			}
			return time.Duration(*a.AccessToken.ExpiresIn) * time.Second, false, nil
		}
	}
	return time.Duration(0), false, fmt.Errorf("not found key: %w", err)
}
