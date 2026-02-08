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

<<<<<<<< HEAD:veles/secrets/cloudflareapitoken/cloudflareapitoken.go
package cloudflareapitoken

// CloudflareAPIToken is a Veles Secret that holds relevant information for a
// Cloudflare API Token. The detector identifies 40-character alphanumeric tokens
// (including underscores and hyphens) in three formats:
// - Environment variable assignments (e.g., CLOUDFLARE_API_TOKEN=token)
// - JSON key-value pairs (e.g., "cloudflare_api_token": "token")
// - YAML configurations (e.g., cloudflare_api_token: token)
type CloudflareAPIToken struct {
	Token string
========
package source

import (
	"context"

	"github.com/google/osv-scalibr/enricher/govulncheck/source/internal"
	vulnpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// GovulncheckClient is an interface for running govulncheck on a Go module.
type GovulncheckClient interface {
	RunGovulncheck(ctx context.Context, absModDir string, vulns []*vulnpb.Vulnerability, goVersion string) (map[string][]*internal.Finding, error)
	GoToolchainAvailable(ctx context.Context) bool
>>>>>>>> main:enricher/govulncheck/source/gvcinterface.go
}
