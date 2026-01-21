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

// Package composerpackagist contains an extractor for Composer Packagist credentials.
package composerpackagist

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "secrets/composerpackagist"
)

// Credential represents Composer Packagist credentials
// used for private Composer / Packagist repositories.
//
// When extracted from auth.json: Host, Username, and Password are populated.
// When extracted from composer.json: Host and RepositoryURL are populated.
//
// Note: The same host may appear in two separate secrets (one from each file).
// Use the Host field to correlate credentials with repository URLs.
//
// Validation Considerations:
// - Credentials from auth.json can be validated by attempting HTTP Basic auth to the host
// - Repository URLs from composer.json can be validated by checking if the URL is accessible
// - Full validation requires correlating both secrets by matching the Host field
type Credential struct {
	Host          string
	Username      string
	Password      string
	RepositoryURL string
}

// Extractor extracts Composer Packagist credentials.
type Extractor struct{}

// New returns a new Composer Packagist extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name returns the extractor name.
func (e *Extractor) Name() string {
	return Name
}

// Version returns the extractor version.
func (e *Extractor) Version() int {
	return 0
}

// Requirements returns the extractor requirements.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired determines whether a file should be scanned.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	base := path.Base(api.Path())
	return base == "auth.json" || base == "composer.json"
}

// authJSON represents ~/.config/composer/auth.json.
type authJSON struct {
	HTTPBasic map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"http-basic"`
}

// composerJSON represents composer.json (minimal fields only).
type composerJSON struct {
	Repositories []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"repositories"`
}

// Extract extracts Composer Packagist credentials from auth.json
// and repository URLs from composer.json.
//
// Design Decision: This extractor produces TWO separate secrets when both files exist:
// 1. From auth.json: host, username, password (no repository_url)
// 2. From composer.json: host, repository_url (no username/password)
//
// Rationale:
// - The extractor architecture processes files independently
// - Cross-file state sharing is unreliable due to unpredictable file processing order
// - Each file produces its own secret with the data it contains
// - The 'host' field can be used to correlate the two secrets in post-processing
func (e *Extractor) Extract(ctx context.Context,
	input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	switch path.Base(input.Path) {
	case "composer.json":
		return e.extractComposerJSON(input)
	case "auth.json":
		return e.extractAuthJSON(input)
	default:
		return inventory.Inventory{}, nil
	}
}

// extractComposerJSON extracts repository URLs from composer.json.
func (e *Extractor) extractComposerJSON(input *filesystem.ScanInput) (inventory.Inventory, error) {
	var data composerJSON
	if err := json.NewDecoder(input.Reader).Decode(&data); err != nil {
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	var secrets []*inventory.Secret
	for _, repo := range data.Repositories {
		if repo.URL != "" {
			host := extractHostFromURL(repo.URL)
			secrets = append(secrets, &inventory.Secret{
				Secret: Credential{
					Host:          host,
					Username:      "",
					Password:      "",
					RepositoryURL: repo.URL,
				},
				Location: input.Path,
			})
		}
	}

	if len(secrets) == 0 {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{
		Secrets: secrets,
	}, nil
}

// extractAuthJSON extracts HTTP Basic credentials from auth.json.
func (e *Extractor) extractAuthJSON(input *filesystem.ScanInput) (inventory.Inventory, error) {
	var data authJSON
	if err := json.NewDecoder(input.Reader).Decode(&data); err != nil {
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	if len(data.HTTPBasic) == 0 {
		return inventory.Inventory{}, nil
	}

	var secrets []*inventory.Secret
	for host, creds := range data.HTTPBasic {
		if creds.Username == "" || creds.Password == "" {
			continue
		}
		secrets = append(secrets, &inventory.Secret{
			Secret: Credential{
				Host:          host,
				Username:      creds.Username,
				Password:      creds.Password,
				RepositoryURL: "",
			},
			Location: input.Path,
		})
	}

	if len(secrets) == 0 {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{
		Secrets: secrets,
	}, nil
}

// extractHostFromURL extracts the host from a URL string.
func extractHostFromURL(urlStr string) string {
	host := urlStr
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
