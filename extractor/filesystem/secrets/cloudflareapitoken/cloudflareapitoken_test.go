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

package cloudflareapitoken_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/cloudflareapitoken"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/fakefs"
	velescloudflare "github.com/google/osv-scalibr/veles/secrets/cloudflareapitoken"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantScan bool
	}{
		{
			name:     "cloudflared config",
			path:     "/home/user/.cloudflared/config.yml",
			wantScan: true,
		},
		{
			name:     "cloudflare.toml",
			path:     "/project/cloudflare.toml",
			wantScan: true,
		},
		{
			name:     "cloudflare.yaml",
			path:     "/config/cloudflare.yaml",
			wantScan: true,
		},
		{
			name:     "cloudflare.yml",
			path:     "/app/cloudflare.yml",
			wantScan: true,
		},
		{
			name:     "cloudflare.json",
			path:     "/settings/cloudflare.json",
			wantScan: true,
		},
		{
			name:     "file in cloudflare directory",
			path:     "/project/cloudflare/config.txt",
			wantScan: true,
		},
		{
			name:     "file with cloudflare in name",
			path:     "/project/my-cloudflare-settings.yaml",
			wantScan: true,
		},
		{
			name:     "case insensitive - Cloudflare",
			path:     "/project/Cloudflare.toml",
			wantScan: true,
		},
		{
			name:     "case insensitive - CLOUDFLARE",
			path:     "/settings/CLOUDFLARE.json",
			wantScan: true,
		},
		{
			name:     "wrangler.toml without cloudflare in path",
			path:     "/project/wrangler.toml",
			wantScan: false,
		},
		{
			name:     ".env file without cloudflare in path",
			path:     "/project/.env",
			wantScan: false,
		},
		{
			name:     "terraform.tfvars without cloudflare in path",
			path:     "/infrastructure/terraform.tfvars",
			wantScan: false,
		},
		{
			name:     "random file",
			path:     "/home/user/document.txt",
			wantScan: false,
		},
		{
			name:     "package.json",
			path:     "/project/package.json",
			wantScan: false,
		},
		{
			name:     "config.yml in different directory",
			path:     "/etc/config.yml",
			wantScan: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cloudflareapitoken.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.wantScan {
				t.Errorf("FileRequired() = %v, want %v", got, tt.wantScan)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		content         string
		wantSecretFound bool
		wantSecret      string
	}{
		{
			name: "Cloudflare token in wrangler.toml",
			path: "wrangler.toml",
			content: `name = "my-worker"
account_id = "1234567890abcdef1234567890abcdef"
CLOUDFLARE_API_TOKEN = "1234567890abcdefghijklmnopqrstuvwxyz1234"
`,
			wantSecretFound: true,
			wantSecret:      "1234567890abcdefghijklmnopqrstuvwxyz1234",
		},
		{
			name: "Cloudflare token in .env",
			path: ".env",
			content: `DB_HOST=localhost
CF_API_TOKEN="abc123xyz456def789ghi012jkl345mno678pqrs"
PORT=3000`,
			wantSecretFound: true,
			wantSecret:      "abc123xyz456def789ghi012jkl345mno678pqrs",
		},
		{
			name: "Cloudflare token in cloudflare.yaml",
			path: "cloudflare.yaml",
			content: `tunnel: my-tunnel
credentials-file: /path/to/cert
cloudflare_api_token: "1234567890abcdefghijklmnopqrstuvwxyz1234"`,
			wantSecretFound: true,
			wantSecret:      "1234567890abcdefghijklmnopqrstuvwxyz1234",
		},
		{
			name: "No token in file",
			path: "wrangler.toml",
			content: `name = "my-worker"
account_id = "short"
description = "My worker"`,
			wantSecretFound: false,
			wantSecret:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := cloudflareapitoken.New(nil)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			r := strings.NewReader(tt.content)
			input := &filesystem.ScanInput{
				Path:   tt.path,
				Reader: io.NopCloser(r),
				Root:   "/",
				FS:     scalibrfs.DirFS("/"),
				Info:   &fakefs.FakeFileInfo{FileName: tt.path},
			}

			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if !tt.wantSecretFound {
				// Expecting no secrets found
				if len(got.Secrets) != 0 {
					t.Errorf("Extract() found %d secrets, want 0", len(got.Secrets))
				}
				return
			}

			// Expecting at least one secret
			if len(got.Secrets) == 0 {
				t.Errorf("Extract() found no secrets, want at least 1")
				return
			}

			// Check that we have a secret with the correct location and secret value
			wantInventory := inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Location: tt.path,
						Secret:   velescloudflare.CloudflareAPIToken{Token: tt.wantSecret},
					},
				},
			}

			if diff := cmp.Diff(wantInventory, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew(t *testing.T) {
	e, err := cloudflareapitoken.New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if e.Name() != cloudflareapitoken.Name {
		t.Errorf("Name() = %v, want %v", e.Name(), cloudflareapitoken.Name)
	}

	if e.Version() != cloudflareapitoken.Version {
		t.Errorf("Version() = %v, want %v", e.Version(), cloudflareapitoken.Version)
	}
}
