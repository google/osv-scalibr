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

// Package gitlabjobtoken contains an Enricher that augments GitLab CI/CD Job Tokens
// with job metadata from the GitLab API.
package gitlabjobtoken

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

const (
	// Name is the unique name of this Enricher.
	Name = "secrets/gitlabjobtoken"

	version                 = 1
	defaultGitlabJobAPIPath = "/api/v4/job"
)

var _ enricher.Enricher = &Enricher{}

// Enricher augments GitLab CI/CD Job Tokens with job metadata.
type Enricher struct {
	httpClient *http.Client
}

// New creates a new Enricher with default configuration.
func New() enricher.Enricher {
	return &Enricher{
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

// Enrich augments GitLab CI/CD Job Tokens with job metadata obtained from the API.
func (e *Enricher) Enrich(ctx context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	for i, s := range inv.Secrets {
		if err := ctx.Err(); err != nil {
			return err
		}
		tok, ok := s.Secret.(gitlab.CIJobToken)
		if !ok || tok.Token == "" {
			continue
		}

		// Fetch job metadata from GitLab API
		if err := e.enrichToken(ctx, &tok); err != nil {
			// Non-fatal: skip enrichment on error
			continue
		}
		inv.Secrets[i].Secret = tok
	}
	return nil
}

// jobResponse represents the relevant fields from GitLab's job API response
type jobResponse struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	User   struct {
		Username string `json:"username"`
	} `json:"user"`
	Pipeline struct {
		ProjectID int64 `json:"project_id"`
	} `json:"pipeline"`
}

func (e *Enricher) enrichToken(ctx context.Context, tok *gitlab.CIJobToken) error {
	// Determine the endpoint based on hostname
	hostname := tok.Hostname
	if hostname == "" {
		hostname = "gitlab.com"
	}

	// Check if hostname already includes protocol
	endpoint := hostname
	if !strings.HasPrefix(hostname, "http://") && !strings.HasPrefix(hostname, "https://") {
		endpoint = "https://" + hostname
	}
	endpoint += defaultGitlabJobAPIPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Job-Token", tok.Token)

	res, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http GET: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		// Treat non-200 as non-fatal; skip enrichment
		_, _ = io.Copy(io.Discard, res.Body)
		return nil
	}

	var jobResp jobResponse
	if err := json.NewDecoder(res.Body).Decode(&jobResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// Populate only important metadata
	tok.JobID = jobResp.ID
	tok.Status = jobResp.Status
	tok.Username = jobResp.User.Username
	tok.ProjectID = jobResp.Pipeline.ProjectID

	return nil
}
