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

// Package pgpass provides an extractor for identifying secrets in .pgpass files.
package pgpass

import (
	"bufio"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// Pgpass is a Veles Secret that holds relevant information for a [Postgres Pgpass](https://www.postgresql.org/docs/current/libpq-pgpass.html).
type Pgpass struct {
	Hostname string
	Port     string
	Database string
	Username string
	Password string
}

const (
	// Name is the unique name of this extractor.
	Name = "secrets/pgpass"
)

var (
	// pgpassRe is a regular expression that matches the content of a pgpass file entry
	//
	// Reference:
	// - https://www.postgresql.org/docs/current/libpq-pgpass.html
	//
	// Every entry in the pgpass file is composed by the following fields:
	// hostname:port:database:username:password
	//
	//   - hostname: matches any character except the `:` (that is currently used for separating fields)
	//   - port: matches numbers until 5 digits and * (wildcard)
	//     this group can match ports > 65535 but it is a compromise for regex performance
	//   - database: same as hostname
	//   - username: same as hostname
	//   - password: can match any allowed characters but colons must be escaped
	pgpassRe = regexp.MustCompile(`^([ -9;-~]+):(\*|[0-9]{1,5}):([ -9;-~]+):([ -9;-~]+):((?:\\:|[ -9;-~])+)$`)
)

// Extractor extracts postres credentials from .pgpass files.
type Extractor struct{}

// New returns a pgpass extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file is a .pgpass file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == ".pgpass"
}

// Extract extracts PostgreSQL credentials from .pgpass file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	scanner := bufio.NewScanner(input.Reader)
	var secrets []*inventory.Secret

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments.
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := pgpassRe.FindStringSubmatch(line)

		if len(matches) == 6 {
			password := matches[5]
			// Skip entries where the password is a single '*'
			if password == "*" {
				continue
			}

			pgpassSecret := Pgpass{
				Hostname: matches[1],
				Port:     matches[2],
				Database: matches[3],
				Username: matches[4],
				Password: matches[5],
			}

			secrets = append(secrets, &inventory.Secret{
				Secret:   pgpassSecret,
				Location: input.Path,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return inventory.Inventory{}, fmt.Errorf("error reading .pgpass file: %w", err)
	}

	return inventory.Inventory{Secrets: secrets}, nil
}
