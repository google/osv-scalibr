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
type Credential struct {
	Host     string
	Username string
	Password string
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
	return base == "auth.json"
}

// authJSON represents ~/.config/composer/auth.json.
type authJSON struct {
	HTTPBasic map[string]struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"http-basic"`
}

// Extract extracts Composer Packagist credentials from auth.json.
func (e *Extractor) Extract(ctx context.Context,
	input *filesystem.ScanInput,
) (inventory.Inventory, error) {
	return e.extractAuthJSON(input)
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
				Host:     host,
				Username: creds.Username,
				Password: creds.Password,
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
