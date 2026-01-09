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

// Package hcpidentity contains an Enricher that augments HCP access tokens
// with identity metadata from the caller-identity endpoint.
package hcpidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/hcp"
)

const (
	// Name is the unique name of this Enricher.
	Name = "secrets/hcpidentity"

	version        = 1
	defaultBaseURL = "https://api.cloud.hashicorp.com"
)

var _ enricher.Enricher = &Enricher{}

// Enricher augments HCP access tokens with identity metadata.
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

// Enrich augments HCP access tokens with identity metadata obtained from the API.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	for _, s := range inv.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		tok, ok := s.Secret.(hcp.AccessToken)
		if !ok || tok.Token == "" {
			continue
		}
		// Call caller-identity. Do not fail the entire enrichment if this fails.
		id, err := e.fetchCallerIdentity(ctx, tok.Token)
		if err != nil {
			continue
		}
		tok.OrganizationID = id.OrganizationID
		tok.ProjectID = id.ProjectID
		tok.PrincipalID = id.PrincipalID
		tok.PrincipalType = id.PrincipalType
		tok.ServiceName = id.ServiceName
		tok.GroupIDs = id.GroupIDs
		s.Secret = tok
	}
	return nil
}

// identityResponse represents the HCP caller-identity endpoint response.
// Only some of the fields are included for enrichment.
// See https://developer.hashicorp.com/hcp/api-docs/identity#IamService_GetCallerIdentity
type identityResponse struct {
	Principal struct {
		ID    string   `json:"id"`
		Type  string   `json:"type"`
		Group []string `json:"group_ids"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		Service struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			Organization string `json:"organization_id"`
			Project      string `json:"project_id"`
		} `json:"service"`
	} `json:"principal"`
}

type identity struct {
	OrganizationID string
	ProjectID      string
	PrincipalID    string
	PrincipalType  string
	ServiceName    string
	GroupIDs       []string
	UserEmail      string
	UserID         string
}

func (e *Enricher) fetchCallerIdentity(ctx context.Context, bearer string) (identity, error) {
	url := e.baseURL + "/iam/2019-12-10/caller-identity"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return identity{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	res, err := e.httpClient.Do(req)
	if err != nil {
		return identity{}, fmt.Errorf("http GET: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		// Treat non-200 as non-fatal; skip enrichment.
		_, _ = io.Copy(io.Discard, res.Body)
		return identity{}, nil
	}
	var raw identityResponse
	if err := json.NewDecoder(res.Body).Decode(&raw); err != nil {
		return identity{}, fmt.Errorf("decode response: %w", err)
	}
	return identity{
		OrganizationID: raw.Principal.Service.Organization,
		ProjectID:      raw.Principal.Service.Project,
		PrincipalID:    raw.Principal.ID,
		PrincipalType:  raw.Principal.Type,
		ServiceName:    raw.Principal.Service.Name,
		GroupIDs:       raw.Principal.Group,
		UserEmail:      raw.Principal.User.Email,
		UserID:         raw.Principal.User.ID,
	}, nil
}
