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

package onepasswordconnecttoken_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/onepasswordconnecttoken"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/extracttest"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		wantRequired bool
	}{
		{
			name:         "valid onepassword json file",
			path:         "/project/onepassword-token.json",
			wantRequired: true,
		},
		{
			name:         "valid 1password json file",
			path:         "/project/1password-config.json",
			wantRequired: true,
		},
		{
			name:         "onepassword uppercase",
			path:         "/project/ONEPASSWORD-settings.json",
			wantRequired: true,
		},
		{
			name:         "invalid extension",
			path:         "/project/onepassword-token.txt",
			wantRequired: false,
		},
		{
			name:         "no onepassword in name",
			path:         "/project/config.json",
			wantRequired: false,
		},
		{
			name:         "not json file",
			path:         "/tmp/var/scalibr",
			wantRequired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := onepasswordconnecttoken.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("onepasswordconnecttoken.New failed: %v", err)
			}
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
			name: "valid_onepassword_connect_token",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/valid",
			},
			wantSecrets: []*inventory.Secret{
				{
					Secret: onepasswordconnecttoken.OnePasswordConnectToken{
						DeviceUUID:        "yrkdmusoblmgm6siuj4kcssxke",
						Version:           "2",
						EncryptedData:     "yQVzCjBZa5mRMHsT5DQF9y9NWR0oY1ZudueqUCuKEUm4agXFGagMLiZJgwX4zn8nCfhtEWgA0OUo10HlR-oMx6hpHw8QsW8Y3e61t0en40LHAzMwjIZtIn_NFKAzSAMJRU3sv4Kz70YsZZopK9Jsgx4czkCcYqgr-3KxVczVpBhsq6PhPYh-xsr8a2tDQ2_ZWYQgTyUH51vV0ZfNOH81Wa6M6Xc2uAtBLx3uxP7odK0h1CH6RhEmokX1lwPy8C5d0wKRF-DJGpzEUZ9wenic8BtDVO00rAOQJT1sUZM6YHPcxL6mco3kWhuXtPVHBcWbDPWWK-WHoRTI_qUKBg3yof-19Y9DBwT2ScwBFbssZgCcQ7pXy8GK_VP0n381zMDbD5w0ZD3qA58jYWTK36_ZWkbcFv_jG1rvk1O5DuGnlQT3cQxv9ELUKT6FB9qqvGjvkWZzKDfljHQ7QThlOzG5iVFYkWKXEAW60BOQmRwI4xikrPvf3KjywE2IFxliUWxt5AMHSWrknyEoHSLkpSThLDL4EhePptc9UBW6rkYhVsC6ZUkiOIIQ1hOBPRqctAteacuCGD1I9CI3x5CgnEL7TNPX_njDO_fkvQBJUBauLaPP7ObjyPDnWLOAKROELWjrFA",
						EncryptionKeyID:   "localauthv2keykid",
						IV:                "nHE-eIYl0_YgVo14",
						UniqueKeyID:       "pol5dybe7lxax42ha6r7rwwdm4",
						VerifierSalt:      "JD6cq4PDx8biZ_WIEo8sJQ",
						VerifierLocalHash: "lLjGM419fBfty9S-a7BwXBLsl40QL0xWmReBF2r9hM8",
					},
					Location: "testdata/valid",
				},
			},
		},
		{
			name: "invalid_json",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid",
			},
			wantSecrets: nil,
		},
		{
			name: "missing_required_fields",
			inputConfigFile: extracttest.ScanInputMockConfig{
				Path: "testdata/incomplete",
			},
			wantSecrets: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extr, err := onepasswordconnecttoken.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("onepasswordconnecttoken.New failed: %v", err)
			}

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
			if diff := cmp.Diff(wantInv, got, cmpopts.IgnoreUnexported(onepasswordconnecttoken.OnePasswordConnectToken{})); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.inputConfigFile.Path, diff)
			}
		})
	}
}
