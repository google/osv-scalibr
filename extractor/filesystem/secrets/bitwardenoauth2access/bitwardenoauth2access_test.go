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

package bitwardenoauth2access_test

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/bitwardenoauth2access"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/fakefs"
	velesbitwarden "github.com/google/osv-scalibr/veles/secrets/bitwardenoauth2access"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantScan bool
	}{
		{
			name:     "Bitwarden CLI data.json",
			path:     "/home/user/.config/Bitwarden CLI/data.json",
			wantScan: true,
		},
		{
			name:     "Bitwarden CLI data.json lowercase",
			path:     "/home/user/.config/bitwarden cli/data.json",
			wantScan: true,
		},
		{
			name:     "case insensitive - BITWARDEN CLI",
			path:     "/home/user/BITWARDEN CLI/data.json",
			wantScan: true,
		},
		{
			name:     "bitwarden cli but not data.json",
			path:     "/home/user/.config/Bitwarden CLI/config.json",
			wantScan: false,
		},
		{
			name:     "bitwarden without CLI directory",
			path:     "/snap/bitwarden/current/data.json",
			wantScan: false,
		},
		{
			name:     "data.json without bitwarden in path",
			path:     "/home/user/.config/someapp/data.json",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := bitwardenoauth2access.New(nil)
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
		name             string
		path             string
		content          string
		wantSecretFound  bool
		wantClientID     string
		wantClientSecret string
	}{
		{
			name: "Bitwarden data.json with apiKeyClientSecret",
			path: "data.json",
			content: `{
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMwMDA...",
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_apiKeyClientSecret": "N8N2xWg4FV8lusbl5CHBb5XRil6kOa",
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_refreshToken": "someRefreshToken"
}`,
			wantSecretFound:  true,
			wantClientID:     "d351d93b-adb0-4714-bbef-a11100fff9cc",
			wantClientSecret: "N8N2xWg4FV8lusbl5CHBb5XRil6kOa",
		},
		{
			name: "Bitwarden data.json with different UUID",
			path: "data.json",
			content: `{
  "user_a1b2c3d4-e5f6-7890-abcd-ef1234567890_token_apiKeyClientSecret": "AbCdEfGhIjKlMnOpQrStUvWxYz123456"
}`,
			wantSecretFound:  true,
			wantClientID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantClientSecret: "AbCdEfGhIjKlMnOpQrStUvWxYz123456",
		},
		{
			name: "No apiKeyClientSecret in file",
			path: "data.json",
			content: `{
  "user_d351d93b-adb0-4714-bbef-a11100fff9cc_token_accessToken": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjMwMDA...",
  "someOtherKey": "someValue"
}`,
			wantSecretFound: false,
		},
		{
			name:            "Empty file",
			path:            "data.json",
			content:         `{}`,
			wantSecretFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := bitwardenoauth2access.New(nil)
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
						Secret: velesbitwarden.Token{
							ClientID:     tt.wantClientID,
							ClientSecret: tt.wantClientSecret,
						},
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
	e, err := bitwardenoauth2access.New(nil)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if e.Name() != bitwardenoauth2access.Name {
		t.Errorf("Name() = %v, want %v", e.Name(), bitwardenoauth2access.Name)
	}

	if e.Version() != bitwardenoauth2access.Version {
		t.Errorf("Version() = %v, want %v", e.Version(), bitwardenoauth2access.Version)
	}
}
