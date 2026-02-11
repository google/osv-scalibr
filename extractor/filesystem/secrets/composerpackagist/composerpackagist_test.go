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
		{name: "nested auth.json", path: "project/auth.json", wantRequired: true},
		{name: "composer.json", path: "composer.json", wantRequired: false},
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
						Host:     "repo.packagist.com",
						Username: "testuser",
						Password: "testpass123",
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
			name: "multiple_hosts",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/multiple_hosts/auth.json",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: composerpackagist.Credential{
						Host:     "repo1.example.com",
						Username: "user1",
						Password: "pass1",
					},
					Location: "testdata/multiple_hosts/auth.json",
				},
				{
					Secret: composerpackagist.Credential{
						Host:     "repo2.example.com",
						Username: "user2",
						Password: "pass2",
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
