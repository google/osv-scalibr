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

package composerpackagist_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/composerpackagist"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{name: "auth.json", path: "auth.json", wantRequired: true},
		{name: "composer.json", path: "composer.json", wantRequired: true},
		{name: "nested auth.json", path: "project/auth.json", wantRequired: true},
		{name: "nested composer.json", path: "project/composer.json", wantRequired: true},
		{name: "package.json", path: "package.json", wantRequired: false},
		{name: "other.json", path: "other.json", wantRequired: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := composerpackagist.New().(*composerpackagist.Extractor)
			if got := e.FileRequired(simplefileapi.New(tt.path, nil)); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name            string
		wantSecrets     []*inventory.Secret
		inputConfigFile extracttest.ScanInputMockConfig
	}{
		{
			name: "valid_composer_http_basic_credentials",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/valid/auth.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "repo.packagist.com",
						Username:      "testuser",
						Password:      "testpass123",
						RepositoryURL: "",
					},
					Location: "testdata/valid/auth.json",
				},
			},
		},
		{
			name: "invalid_json",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid/auth.json",
			},
			wantSecrets: nil,
		},
		{
			name: "incomplete_credentials",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/incomplete/auth.json",
			},
			wantSecrets: nil,
		},
		{
			name: "missing_password",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/missing_password/auth.json",
			},
			wantSecrets: nil,
		},
		{
			name: "composer_json_with_repo_url",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/composer_only/composer.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "private-repo.example.com",
						Username:      "",
						Password:      "",
						RepositoryURL: "https://private-repo.example.com",
					},
					Location: "testdata/composer_only/composer.json",
				},
			},
		},
		{
			name: "multiple_hosts",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_hosts/auth.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "repo1.example.com",
						Username:      "user1",
						Password:      "pass1",
						RepositoryURL: "",
					},
					Location: "testdata/multiple_hosts/auth.json",
				},
				{
					Secret: composerpackagist.Credential{
						Host:          "repo2.example.com",
						Username:      "user2",
						Password:      "pass2",
						RepositoryURL: "",
					},
					Location: "testdata/multiple_hosts/auth.json",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := composerpackagist.New().(*composerpackagist.Extractor)

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("Extract() unexpected error = %v", err)
			}

			if tt.wantSecrets == nil {
				// For invalid cases, we expect empty inventory
				wantInv := inventory.Inventory{}
				if diff := cmp.Diff(wantInv, got); diff != "" {
					t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
				}
				return
			}

			wantInv := inventory.Inventory{Secrets: tt.wantSecrets}
			sortSecrets := cmpopts.SortSlices(func(a, b *inventory.Secret) bool {
				ca, oka := a.Secret.(composerpackagist.Credential)
				cb, okb := b.Secret.(composerpackagist.Credential)
				if !oka || !okb {
					return false
				}
				return ca.Host < cb.Host
			})
			if diff := cmp.Diff(wantInv, got, cmpopts.IgnoreUnexported(composerpackagist.Credential{}), sortSecrets); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}

// TestExtractComposerJSON tests that composer.json files extract repository URLs
func TestExtractComposerJSON(t *testing.T) {
	tests := []struct {
		name            string
		wantSecrets     []*inventory.Secret
		inputConfigFile extracttest.ScanInputMockConfig
	}{
		{
			name: "composer_json_with_repositories",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/with_repo/composer.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "repo.packagist.com",
						Username:      "",
						Password:      "",
						RepositoryURL: "https://repo.packagist.com",
					},
					Location: "testdata/with_repo/composer.json",
				},
			},
		},
		{
			name: "composer_json_only",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/composer_only/composer.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "private-repo.example.com",
						Username:      "",
						Password:      "",
						RepositoryURL: "https://private-repo.example.com",
					},
					Location: "testdata/composer_only/composer.json",
				},
			},
		},
		{
			name: "composer_json_no_urls",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/composer_no_urls/composer.json",
			},
			wantSecrets: nil,
		},
		{
			name: "composer_json_empty_urls",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/composer_empty_urls/composer.json",
			},
			wantSecrets: nil,
		},
		{
			name: "composer_json_mixed_urls",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/composer_mixed_urls/composer.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:          "valid-repo.example.com",
						Username:      "",
						Password:      "",
						RepositoryURL: "https://valid-repo.example.com",
					},
					Location: "testdata/composer_mixed_urls/composer.json",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr := composerpackagist.New().(*composerpackagist.Extractor)

			scanInput := extracttest.GenerateScanInputMock(t, tt.inputConfigFile)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if err != nil {
				t.Fatalf("Extract() unexpected error = %v", err)
			}

			if tt.wantSecrets == nil {
				wantInv := inventory.Inventory{}
				if diff := cmp.Diff(wantInv, got); diff != "" {
					t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
				}
				return
			}

			wantInv := inventory.Inventory{Secrets: tt.wantSecrets}
			if diff := cmp.Diff(wantInv, got, cmpopts.IgnoreUnexported(composerpackagist.Credential{})); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}

// TestExtractBothFiles tests that processing both files produces two separate secrets
// that can be correlated by the Host field.
func TestExtractBothFiles(t *testing.T) {
	extr := composerpackagist.New().(*composerpackagist.Extractor)

	// Process composer.json
	composerInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/with_repo/composer.json",
	})
	composerInv, err := extr.Extract(t.Context(), &composerInput)
	extracttest.CloseTestScanInput(t, composerInput)
	if err != nil {
		t.Fatalf("Extract(composer.json) unexpected error = %v", err)
	}

	// Process auth.json
	authInput := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/with_repo/auth.json",
	})
	authInv, err := extr.Extract(t.Context(), &authInput)
	extracttest.CloseTestScanInput(t, authInput)
	if err != nil {
		t.Fatalf("Extract(auth.json) unexpected error = %v", err)
	}

	// Verify we got two separate secrets
	if len(composerInv.Secrets) != 1 {
		t.Errorf("Expected 1 secret from composer.json, got %d", len(composerInv.Secrets))
	}
	if len(authInv.Secrets) != 1 {
		t.Errorf("Expected 1 secret from auth.json, got %d", len(authInv.Secrets))
	}

	// Verify both secrets have the same host for correlation
	if len(composerInv.Secrets) > 0 && len(authInv.Secrets) > 0 {
		composerCred := composerInv.Secrets[0].Secret.(composerpackagist.Credential)
		authCred := authInv.Secrets[0].Secret.(composerpackagist.Credential)

		if composerCred.Host != authCred.Host {
			t.Errorf("Host mismatch: composer=%s, auth=%s", composerCred.Host, authCred.Host)
		}

		// Verify composer secret has URL but no credentials
		if composerCred.RepositoryURL == "" {
			t.Error("composer.json secret should have RepositoryURL")
		}
		if composerCred.Username != "" || composerCred.Password != "" {
			t.Error("composer.json secret should not have credentials")
		}

		// Verify auth secret has credentials but no URL
		if authCred.Username == "" || authCred.Password == "" {
			t.Error("auth.json secret should have credentials")
		}
		if authCred.RepositoryURL != "" {
			t.Error("auth.json secret should not have RepositoryURL")
		}
	}
}
