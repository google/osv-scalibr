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

// Package ibmcloudexpiration contains an Enricher that augments IBM Cloud User Keys
// with expiration metadata from the apikeys details endpoint.
package ibmcloudexpiration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/ibmclouduserkey"
)

const (
	// Name is the unique name of this Enricher.
	Name = "secrets/ibmcloudexpiration"

	version        = 1
	defaultBaseURL = "https://iam.cloud.ibm.com"
)

var _ enricher.Enricher = &Enricher{}

// Enricher augments IBM Cloud User Keys with expiration metadata.
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

// Enrich augments IBM Cloud User Keys with expiration metadata obtained from the API.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	for _, s := range inv.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		tok, ok := s.Secret.(ibmclouduserkey.IBMCloudUserSecret)
		if !ok || tok.Key == "" {
			continue
		}

		metadataPtr, err := e.fetchExpiration(ctx, tok.Key)
		if err != nil {
			continue
		}
		tok.Metadata = metadataPtr
		s.Secret = tok
	}
	return nil
}

// authorizationResponse represents the Bearer Token Generation response
// Only some of the fields are included for enrichment.
// See https://cloud.ibm.com/docs/account?topic=account-iamtoken_from_apikey
type authorizationResponse struct {
	BearerToken string `json:"access_token"`
}

// apiKeyResponse represents the API Key details.
// Only some of the fields are included for enrichment.
// See https://cloud.ibm.com/apidocs/iam-identity-token-api#get-api-keys-details
type apiKeyResponse struct {
	ExpiresAt *string `json:"expires_at"`
}

func (e *Enricher) getBearerToken(ctx context.Context, apiKey string) (string, error) {
	url := e.baseURL + "/identity/token"
	reqBody := []byte("grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=" + apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http POST: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// Treat non-200 as non-fatal; skip enrichment.
		_, _ = io.Copy(io.Discard, res.Body)
		return "", nil
	}
	var tr authorizationResponse

	if err := json.NewDecoder(res.Body).Decode(&tr); err != nil {
		return "", err
	}

	return tr.BearerToken, nil
}

func (e *Enricher) fetchExpiration(ctx context.Context, apiKey string) (*ibmclouduserkey.Metadata, error) {
	bearerToken, err := e.getBearerToken(ctx, apiKey)
	if err != nil || bearerToken == "" {
		return nil, err
	}
	url := e.baseURL + "/v1/apikeys/details"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("IAM-Apikey", apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http GET: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// Treat non-200 as non-fatal; skip enrichment.
		_, _ = io.Copy(io.Discard, res.Body)
		return nil, nil
	}

	var resp apiKeyResponse

	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nil, err
	}

	if resp.ExpiresAt == nil {
		metadataPtr := &ibmclouduserkey.Metadata{ExpireTime: nil, NeverExpires: true}
		return metadataPtr, nil
	}
	metadataPtr := &ibmclouduserkey.Metadata{NeverExpires: false}
	metadataPtr.ExpireTime = resp.ExpiresAt
	return metadataPtr, nil
}
